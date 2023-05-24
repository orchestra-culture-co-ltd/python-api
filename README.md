## GOAL
We supply Python API for accessing Orchestra Pipeline System so that you can integrate it with your tools.  



## INSTALL DEPENDENCIES
```
pip install --upgrade pip
or
pip install -i http://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn --upgrade pip

pip install certifi pytz future six pyyaml typing urllib3==1.26
```


## EXAMPLE
```
from api import Api

base_url = "https://trial.orchestra-technology.com"
proxy_addr = None


client = Api(base_url, "api_user@orchestra-technology.com", api_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", proxy=proxy_addr)
client.login()

client.read("Task", fields=["id", "name"], pages={"page": 1, "page_size": 5})
```
