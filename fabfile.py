from fabric.api import *
from fabric.contrib.files import *

env.hosts = ['184.106.93.74']
env.user = 'brendan'

def deploy_all():
    install_apache()
    install_mysql('bbb123')
    install_phpmyadmin()
    install_git()
    create_database('wp_codebetter',
                    'root',
                    'bbb123',
                    'dbuser',
                    'dbpass')
    
    copy_git_database('wp_codebetter',
                      'git://github.com/btompkins/CodeBetter.Com-MySql.git')
    install_mail()
    install_ftp()
    setup_website('codebetter.com')
    copy_git_website('codebetter.com',
                     'git://github.com/btompkins/CodeBetter.Com-Wordpress.git',
                     'wp_codebetter',
                     'dbuser',
                     'dbpass')
    
def new_user(admin_username, admin_password):   
    env.user = 'root'
    env.password = 'test.codebetter.comtx65bUXO4'
    
    # Create the admin group and add it to the sudoers file
    admin_group = 'admin'
    runcmd('addgroup {group}'.format(group=admin_group))
    runcmd('echo "%{group} ALL=(ALL) ALL" >> /etc/sudoers'.format(
        group=admin_group))
    
    # Create the new admin user (default group=username); add to admin group
    runcmd('adduser {username} --disabled-password --gecos ""'.format(
        username=admin_username))
    runcmd('adduser {username} {group}'.format(
        username=admin_username,
        group=admin_group))
    
    # Set the password for the new admin user
    runcmd('echo "{username}:{password}" | chpasswd'.format(
        username=admin_username,
        password=admin_password))
    
def upgrade_hosts():
    runcmd('apt-get -y update && apt-get -y dist-upgrade ')

def install_apache():
    runcmd('apt-get -y install apache2 php5 libapache2-mod-php5')
    runcmd('a2enmod rewrite')
    runcmd('a2enmod deflate')
    runcmd('a2enmod expires')
    runcmd('a2enmod headers')
    runcmd('sh -c "echo \'<?php phpinfo( ); ?>\'  > /var/www/info.php"')
    append(['',
            '# Customizations', 'Header unset ETag',
            'FileETag None',
            'ExpiresActive On',
            'ExpiresDefault "access plus 7 days"'], '/etc/apache2/apache2.conf', use_sudo=True)
    runcmd('/etc/init.d/apache2 restart')    
          
def install_mysql(mysql_root_password):
    runcmd('echo "mysql-server mysql-server/root_password select {password}" |' 
           'debconf-set-selections'.format(
        password=mysql_root_password))
    runcmd('echo "mysql-server mysql-server/root_password_again select ' 
           '{password}" | debconf-set-selections'.format(
        password=mysql_root_password))
    runcmd('apt-get -y install mysql-server mysql-client php5-mysql')

def install_phpmyadmin():
    runcmd('DEBIAN_FRONTEND=noninteractive apt-get install -y phpmyadmin')
    runcmd('ln -sv /etc/phpmyadmin/apache.conf '
           '/etc/apache2/conf.d/phpmyadmin.conf')
    runcmd('/etc/init.d/apache2 restart')
    # Now you can point your browser to: http://domain/phpmyadmin    

def install_git():
    runcmd('apt-get -y install git-core')

def create_database(database_name, root_user, root_password, new_user,
                    new_user_password):
    runcmd('mysql --user={root} --password={password} --execute="create '
           'database {database}"'.format(root=root_user,
                                         password=root_password,
                                         database=database_name))
    runcmd('mysql --user={root} --password={password} --execute="CREATE USER '
           '\'{user}\' IDENTIFIED BY \'{userpass}\'"'
           .format(root=root_user,
                   password=root_password,
                   user=new_user,
                   userpass=new_user_password))
    runcmd('mysql --user={root} --password={password} '
           '--execute="GRANT ALL ON {database}.* TO '
           '\'{user}\'@\'localhost\' IDENTIFIED BY \'{userpass}\'"'
           .format(root=root_user,
                   password=root_password,
                   database=database_name,
                   user=new_user,
                   userpass=new_user_password))
    runcmd('mysql --user={root} --password={password} '
           '--execute="FLUSH PRIVILEGES"'
           .format(root=root_user,
                   password=root_password))

def copy_git_database(local_database_name, repository_uri):
    with cd('/var/lib/mysql/{database}'.format(database=local_database_name)):
        sed('/etc/ssh/ssh_config', '#   StrictHostKeyChecking ask',
            'StrictHostKeyChecking no', use_sudo=True)        
        runcmd('rm -r *.*')
        runcmd('git clone {repo} .'.format(repo=repository_uri,
                                           database=local_database_name))

def install_mail():
    runcmd('DEBIAN_FRONTEND=noninteractive apt-get -y install postfix')

def install_ftp():
    runcmd('apt-get -y install vsftpd')
    uncomment('/etc/vsftpd.conf', 'write_enable=YES', use_sudo=True)
    uncomment('/etc/vsftpd.conf', 'local_umask=022', use_sudo=True)   
    uncomment('/etc/vsftpd.conf', 'chroot_local_user=YES', use_sudo=True)
    runcmd('sudo /etc/init.d/vsftpd start')

def setup_website(domain_name):
    runcmd('mkdir /var/www/{domain}'.format(domain=domain_name))
    runcmd('touch /etc/apache2/sites-enabled/{domain}'.format(
        domain=domain_name))
    append(['NameVirtualHost *:80',
            '',
            '<VirtualHost *:80>',
            '   ServerName www.{domain}'.format(domain=domain_name),
            '   ServerAlias {domain} *.{domain}'.format(domain=domain_name),
            '   DocumentRoot /var/www/{domain}'.format(domain=domain_name),
            '</VirtualHost>'],'/etc/apache2/sites-enabled/{domain}'.format(
                domain=domain_name), use_sudo=True)
    # Note that the following will only work once!
    append(['<IfModule mod_rewrite.c>',
        '   RewriteLog "/var/log/apache2/rewrite.log"',
        '   RewriteLogLevel 1',
        '   RewriteMap rewritemap txt:/var/www/{domain}/permalinkmap.txt'
            .format(domain=domain_name),
        '   LimitInternalRecursion 5',
        '</IfModule>'], '/etc/apache2/apache2.conf', use_sudo=True)
    runcmd('/etc/init.d/apache2 restart')

def copy_git_website(domain_name, repository_uri, database_name, database_user, database_password):
    with cd('/var/www/{domain}'.format(domain=domain_name)):
        runcmd('git clone {repo} .'.format(repo=repository_uri))
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_NAME', database_name, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_USER', database_user, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_PASSWORD', database_password, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'SITE_DOMAIN', domain_name, use_sudo=True)
    with cd('/var/www/'):
        runcmd('chown www-data {domain} -fR'.format(domain=domain_name))
        runcmd('/etc/init.d/apache2 restart')

def install_nginx():
        runcmd('echo "deb http://ppa.launchpad.net/nginx/stable/ubuntu '
               '$(lsb_release -cs) main" > '
               '/etc/apt/sources.list.d/nginx-stable-$(lsb_release -cs).list')
        runcmd('apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C300EE8C')
        runcmd('apt-get update')
        runcmd('apt-get -y install nginx')


# Helpers    
def runcmd(arg):
    if env.user != "root":
        sudo("%s" % arg, pty=True)
    else:
        run("%s" % arg, pty=True)


"""
Thanks to

http://www.howtoforge.com/ubuntu_debian_lamp_server
http://serverfault.com/questions/122954/secure-method-of-changing-a-users-password-via-python-script-non-interactively

"""
