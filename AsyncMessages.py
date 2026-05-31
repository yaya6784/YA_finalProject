import threading


class AsyncMessages:
    def __init__(self):
        self.lock_async_msgs = threading.Lock()
        self.async_msgs = {}
        self.sock_by_user = {}

    def add_new_socket(self, new_client_sock):
        self.async_msgs[new_client_sock] = []

    def delete_socket(self, sock):
        if sock in self.async_msgs:
            del self.async_msgs[sock]

    def put_msg_in_async_msgs(self, data, other_sock):
        self.lock_async_msgs.acquire()
        try:
            if other_sock in self.async_msgs:
                self.async_msgs[other_sock].append(data)
        finally:
            self.lock_async_msgs.release()

    def put_msg_by_user(self, data, user):
        self.lock_async_msgs.acquire()
        try:
            if user in self.sock_by_user and self.sock_by_user[user] in self.async_msgs:
                self.async_msgs[self.sock_by_user[user]].append(data)
        finally:
            self.lock_async_msgs.release()

    def get_async_messages_to_send(self, my_sock):
        self.lock_async_msgs.acquire()
        try:
            msgs = self.async_msgs.get(my_sock, [])
            self.async_msgs[my_sock] = []
            return msgs
        finally:
            self.lock_async_msgs.release()
