#!/bin/bash
docker run --privileged --network=host --rm  -v "/etc/timezone:/etc/timezone:ro" -v"/etc/localtime:/etc/localtime:ro" -v /home/ubuntu/super/state/plugins/mesh:/state/plugins/mesh -v /home/ubuntu/super/configs/mesh/:/configs/mesh -v /home/ubuntu/super//configs/base:/configs/base/ --name supermesh mesh
