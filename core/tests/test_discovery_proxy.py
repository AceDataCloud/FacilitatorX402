def test_retired_resource_discovery_routes_are_removed(client):
    for path in ("/discovery/resources", "/discovery/resources/", "/list", "/list/"):
        assert client.get(path).status_code == 404
