from api import Api


base_url = "https://trial.orchestra-technology.com"
proxy_addr = None


"""
Example: login.

client = Api(base_url, "api_user@orchestra-technology.com", api_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", proxy=proxy_addr)
client.login()

"""


"""
Example: create entity type.

task_id =  client.create_entity_type([{"name": "EntityTypeA", "help": "description"}])
client.polling_async_task(task_id)

"""


"""
Example: update entity type.

task_id = client.update_entity_type([{"name": "EntityTypeA", "help": "test description"}])
client.polling_async_task(task_id)

"""


"""
Example: update entity type.

data = client.read("EntityType", fields=["id"], filters=[["name", "is", "EntityTypeA"]], pages={"page":1, "page_size":1})
entity_type_id = data.get("id")
task_id = client.update_entity_type([{"id": entity_type_id, "help": "description"}])
client.polling_async_task(task_id)

"""


"""
Example: delete entity type.

data = client.read("EntityType", fields=["id"], filters=[["name", "is", "EntityTypeA"]], pages={"page":1, "page_size":1})
entity_type_id = data.get("id")
task_id = client.delete_entity_type([{"id": entity_type_id}])
client.polling_async_task(task_id)

"""


"""
Example: create field.

task_id = client.create_field([{"entity_type": "Task", "name": "text", "data_type": "text"}])
client.polling_async_task(task_id)

"""


"""
Example: update field.

task_id = client.update_field([{"entity_type": "Task", "name": "text", "help": "test modify help attribute."}])
client.polling_async_task(task_id)

"""


"""
Example: update field.

result = client.read("Field", ['id'], [['name', 'is', 'text'], ['entity_type__name', 'is', 'Task']], pages={"page":1, "page_size":1})
field_id = result.get("id")
task_id = client.delete_field([{"id": field_id}])
client.polling_async_task(task_id)

"""