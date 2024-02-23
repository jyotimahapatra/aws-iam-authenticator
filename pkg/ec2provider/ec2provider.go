package ec2provider

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/aws-iam-authenticator/pkg"
	"sigs.k8s.io/aws-iam-authenticator/pkg/httputil"
	"sigs.k8s.io/aws-iam-authenticator/pkg/metrics"
)

const (
	// max limit of k8s nodes support
	maxChannelSize = 8000
	// max number of in flight non batched ec2:DescribeInstances request to flow
	maxAllowedInflightRequest = 5
	// default wait interval for the ec2 instance id request which is already in flight
	defaultWaitInterval = 50 * time.Millisecond
	// Making sure the single instance calls waits max till 5 seconds 100* (50 * time.Millisecond)
	totalIterationForWaitInterval = 100
	// Maximum number of instances with which ec2:DescribeInstances call will be made
	maxInstancesBatchSize = 100
	// Maximum time in Milliseconds to wait for a new batch call this also depends on if the instance size has
	// already become 100 then it will not respect this limit
	maxWaitIntervalForBatch = 200
)

// Get a node name from instance ID
type EC2Provider interface {
	GetPrivateDNSName(string) (string, error)
	StartEc2DescribeBatchProcessing()
}

type ec2PrivateDNSCache struct {
	cache map[string]string
	lock  sync.RWMutex
}

type ec2Requests struct {
	set  map[string]bool
	lock sync.RWMutex
}

type ec2ProviderImpl struct {
	ec2                ec2iface.EC2API
	ec2More            ec2iface.EC2API
	privateDNSCache    ec2PrivateDNSCache
	ec2Requests        ec2Requests
	instanceIdsChannel chan string
}

func New(roleARN, region string, qps int, burst int, moreRegion string) EC2Provider {
	dnsCache := ec2PrivateDNSCache{
		cache: make(map[string]string),
		lock:  sync.RWMutex{},
	}
	ec2Requests := ec2Requests{
		set:  make(map[string]bool),
		lock: sync.RWMutex{},
	}
	logrus.Infof("More region %s", moreRegion)
	moreRegion = "us-east-1"
	impl := &ec2ProviderImpl{
		ec2:                ec2.New(newSession(roleARN, region, qps, burst)),
		ec2More:            ec2.New(newSession(roleARN, moreRegion, qps, burst)),
		privateDNSCache:    dnsCache,
		ec2Requests:        ec2Requests,
		instanceIdsChannel: make(chan string, maxChannelSize),
	}

	return impl
}

// Initial credentials loaded from SDK's default credential chain, such as
// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
// Role.

func newSession(roleARN, region string, qps int, burst int) *session.Session {
	sess := session.Must(session.NewSession())
	sess.Handlers.Build.PushFrontNamed(request.NamedHandler{
		Name: "authenticatorUserAgent",
		Fn: request.MakeAddToUserAgentHandler(
			"aws-iam-authenticator", pkg.Version),
	})
	if aws.StringValue(sess.Config.Region) == "" {
		sess.Config.Region = aws.String(region)
	}

	if roleARN != "" {
		logrus.WithFields(logrus.Fields{
			"roleARN": roleARN,
		}).Infof("Using assumed role for EC2 API")

		rateLimitedClient, err := httputil.NewRateLimitedClient(qps, burst)

		if err != nil {
			logrus.Errorf("Getting error = %s while creating rate limited client ", err)
		}

		ap := &stscreds.AssumeRoleProvider{
			Client:   sts.New(sess, aws.NewConfig().WithHTTPClient(rateLimitedClient).WithSTSRegionalEndpoint(endpoints.RegionalSTSEndpoint)),
			RoleARN:  roleARN,
			Duration: time.Duration(60) * time.Minute,
		}

		sess.Config.Credentials = credentials.NewCredentials(ap)
	}
	return sess
}

func (p *ec2ProviderImpl) setPrivateDNSNameCache(id string, privateDNSName string) {
	p.privateDNSCache.lock.Lock()
	defer p.privateDNSCache.lock.Unlock()
	p.privateDNSCache.cache[id] = privateDNSName
}

func (p *ec2ProviderImpl) setRequestInFlightForInstanceId(id string) {
	p.ec2Requests.lock.Lock()
	defer p.ec2Requests.lock.Unlock()
	p.ec2Requests.set[id] = true
}

func (p *ec2ProviderImpl) unsetRequestInFlightForInstanceId(id string) {
	p.ec2Requests.lock.Lock()
	defer p.ec2Requests.lock.Unlock()
	delete(p.ec2Requests.set, id)
}

func (p *ec2ProviderImpl) getRequestInFlightForInstanceId(id string) bool {
	p.ec2Requests.lock.RLock()
	defer p.ec2Requests.lock.RUnlock()
	_, ok := p.ec2Requests.set[id]
	return ok
}

func (p *ec2ProviderImpl) getRequestInFlightSize() int {
	p.ec2Requests.lock.RLock()
	defer p.ec2Requests.lock.RUnlock()
	length := len(p.ec2Requests.set)
	return length
}

// GetPrivateDNS looks up the private DNS from the EC2 API
func (p *ec2ProviderImpl) getPrivateDNSNameCache(id string) (string, error) {
	p.privateDNSCache.lock.RLock()
	defer p.privateDNSCache.lock.RUnlock()
	name, ok := p.privateDNSCache.cache[id]
	if ok {
		return name, nil
	}
	return "", errors.New("instance id not found")
}

// Only calls API if its not in the cache
func (p *ec2ProviderImpl) GetPrivateDNSName(id string) (string, error) {
	logrus.Infof("Calling ec2:DescribeInstances for the InstanceId = %s ", id)
	output, _ := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{id}),
	})

	for _, reservation := range output.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				return aws.StringValue(instance.PrivateDnsName), nil
				//p.setPrivateDNSNameCache(id, privateDNSName)
				//p.unsetRequestInFlightForInstanceId(id)
			}
		}
	}

	logrus.Infof("Calling ec2:DescribeInstances in moreregion for the InstanceId = %s ", id)
	outputMore, _ := p.ec2More.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice([]string{id}),
	})
	for _, reservation := range outputMore.Reservations {
		for _, instance := range reservation.Instances {
			if aws.StringValue(instance.InstanceId) == id {
				return aws.StringValue(instance.PrivateDnsName), nil
				//p.setPrivateDNSNameCache(id, privateDNSName)
				//p.unsetRequestInFlightForInstanceId(id)
			}
		}
	}

	return "", fmt.Errorf("failed to find node %s ", id)
}

func (p *ec2ProviderImpl) StartEc2DescribeBatchProcessing() {
	startTime := time.Now()
	var instanceIdList []string
	for {
		var instanceId string
		select {
		case instanceId = <-p.instanceIdsChannel:
			logrus.Debugf("Received the Instance Id := %s from buffered Channel for batch processing ", instanceId)
			instanceIdList = append(instanceIdList, instanceId)
		default:
			// Waiting for more elements to get added to the buffered Channel
			// And to support the for select loop.
			time.Sleep(20 * time.Millisecond)
		}
		endTime := time.Now()
		/*
			The if statement checks for empty list and ignores to make any ec2:Describe API call
			If elements are less than 100 and time of 200 millisecond has elapsed it will make the
			ec2:DescribeInstances call with as many elements in the list.
			It is also possible that if the system gets more than 99 elements in the list in less than
			200 milliseconds time it will the ec2:DescribeInstances call and that's our whole point of
			optimization here. Also for FYI we have client level rate limiting which is what this
			ec2:DescribeInstances call will make so this call is also rate limited.
		*/
		if (len(instanceIdList) > 0 && (endTime.Sub(startTime).Milliseconds()) > maxWaitIntervalForBatch) || len(instanceIdList) > maxInstancesBatchSize {
			startTime = time.Now()
			dupInstanceList := make([]string, len(instanceIdList))
			copy(dupInstanceList, instanceIdList)
			go p.getPrivateDnsAndPublishToCache(dupInstanceList)
			instanceIdList = nil
		}
	}
}

func (p *ec2ProviderImpl) getPrivateDnsAndPublishToCache(instanceIdList []string) {
	// Look up instance from EC2 API
	logrus.Infof("Making Batch Query to DescribeInstances for %v instances ", len(instanceIdList))
	metrics.Get().EC2DescribeInstanceCallCount.Inc()
	output, _ := p.ec2.DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: aws.StringSlice(instanceIdList),
	})
	if output != nil {
		if output.NextToken != nil {
			logrus.Debugf("Successfully got the batch result , output.NextToken = %s ", *output.NextToken)
		} else {
			logrus.Debugf("Successfully got the batch result , output.NextToken is nil ")
		}
		// Adding the result to privateDNSChache as well as removing from the requestQueueMap.
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				id := aws.StringValue(instance.InstanceId)
				privateDNSName := aws.StringValue(instance.PrivateDnsName)
				p.setPrivateDNSNameCache(id, privateDNSName)
			}
		}
	}
	if p.ec2More != nil {
		output, _ := p.ec2More.DescribeInstances(&ec2.DescribeInstancesInput{
			InstanceIds: aws.StringSlice(instanceIdList),
		})
		if output != nil {
			if output.NextToken != nil {
				logrus.Debugf("Successfully got the batch result , output.NextToken = %s ", *output.NextToken)
			} else {
				logrus.Debugf("Successfully got the batch result , output.NextToken is nil ")
			}
			// Adding the result to privateDNSChache as well as removing from the requestQueueMap.
			for _, reservation := range output.Reservations {
				for _, instance := range reservation.Instances {
					id := aws.StringValue(instance.InstanceId)
					privateDNSName := aws.StringValue(instance.PrivateDnsName)
					p.setPrivateDNSNameCache(id, privateDNSName)
				}
			}
		}
	}

	logrus.Debugf("Removing instances from request Queue after getting response from Ec2")
	for _, id := range instanceIdList {
		p.unsetRequestInFlightForInstanceId(id)
	}
}
