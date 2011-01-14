from fabric.api import *

env.hosts = ['184.106.93.74']
env.password = '[PASSWORD]'


def new_user(username, password):
    env.user = 'root'
    sudo('useradd %s -p %s' % (username, password), pty=True)

def upgrade_hosts(username):
    env.user=username
    sudo('apt-get -y update && apt-get -y dist-upgrade ', pty=True)
