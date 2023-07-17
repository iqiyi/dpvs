# Copyright 2023 IQiYi Inc. All Rights Reserved.
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

import requests
import json

def UpdateService():
    payload="{\"Items\":[{\"inhibited\":false,\"ip\":\"192.168.88.68\",\"port\":80,\"weight\":100}]}"
    url = "http://127.0.0.1:53225/v2/vs/192.168.88.1-80-TCP/rs?healthcheck=true"
    headers = {'content-type': 'application/json'}
    r = requests.put(url, headers=headers, data=payload)
    print(r, r.json())

    url = "http://127.0.0.1:53225/v2/vs/192.168.88.1-80-TCP"
    headers = {'content-type': 'application/json'}
    r = requests.get(url, headers=headers, data=payload)
    print(r, r.json())

if __name__ == '__main__':
    UpdateService()
