def test_resource_discovery_is_retired(client):
    for path in ("/discovery/resources", "/discovery/resources/", "/list", "/list/"):
        response = client.get(path)
        assert response.status_code == 410
        assert response.json()["code"] == "resource_discovery_retired"
        assert response["Cache-Control"] == "no-store"
        assert response["Link"].endswith('>; rel="alternate"')
