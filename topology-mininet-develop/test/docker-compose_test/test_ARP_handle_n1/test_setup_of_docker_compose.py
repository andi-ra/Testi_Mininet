import unittest

# PREREQUISIITO IMPORTANTE FAI PAERTITRE IL FILE DOCKER COMPOSE!!
# topology-mininet-develop/test/docker-compose_test/test_ARP_handle_n1/docker-compose_test.yml
# PREREQUISITO QUANDO FAI DOCKER COMPOSE DOWN RIFAI LA CONNESSIONE SWITCH CONTROLLER


import docker as docker


class MyTestCase(unittest.TestCase):
    def setUp(self):
        global client, lista_container
        client = docker.from_env()
        lista_container = client.containers.list(all=True)

    # @unittest.skip
    def test_controller_Ryu_running(self):
        container_compose = [item for item in lista_container if "controller" in item.name]
        controller = container_compose[0]
        result = controller.exec_run("ps -aux")
        self.assertIn("ryu", result.output.decode())

    def test_switch_connected_to_controller(self):
        container_compose = [item for item in lista_container if "switch" in item.name]
        switch = container_compose[0]
        result = switch.exec_run("ovs-vsctl list controller")
        self.assertIn("is_connected        : true", result.output.decode())

    def test_switch_port_bridge_config_OK(self):
        # Test un po' farlocco....
        container_compose = [item for item in lista_container if "switch" in item.name]
        switch = container_compose[0]
        result = switch.exec_run("ovs-ofctl dump-ports br0")
        self.assertIn("2 ports", result.output.decode())

    def test_switch_iface_bridge_config_OK(self):
        container_compose = [item for item in lista_container if "switch" in item.name]
        switch = container_compose[0]
        result = switch.exec_run("ovs-vsctl list port")
        self.assertIn("eth1", result.output.decode())

    def tearDown(self):
        client.close()


if __name__ == '__main__':
    unittest.main()
