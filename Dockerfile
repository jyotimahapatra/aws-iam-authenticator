# Copyright 2019 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
ARG image=public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-nonroot:2023-09-06-1694026927.2
ARG golang_image=public.ecr.aws/docker/library/golang:1.21.5

FROM --platform=linux/amd64 public.ecr.aws/eks-distro/kubernetes/go-runner:v0.9.0-eks-1-21-4 as go-runner
FROM --platform=linux/amd64 $image
COPY --from=go-runner /usr/local/bin/go-runner /usr/local/bin/go-runner
COPY _output/bin/aws-iam-authenticator__linux_amd64 /aws-iam-authenticator
ENTRYPOINT ["/aws-iam-authenticator"]
