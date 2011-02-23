from fabric.api import *
from fabric.contrib.files import *

env.roledefs = {
    'prx'   : ['184.106.69.38'] ,
    'app'   : ['184.106.69.20'  , #10.180.165.219
               '184.106.69.92'] , #10.180.174.29
    'nginx' : ['184.106.97.207'],
    'db'    : ['184.106.69.141'], #10.180.175.32
    'munin' : ['184.106.83.76']
}

env['184.106.69.20'] = '10.180.165.219'
env['184.106.69.92'] = '10.180.174.29'
env['184.106.69.141'] = '10.180.175.32'
env['184.106.97.207'] = '10.180.174.162'

env.user = 'brendan'

@roles('app')
def log_rotate_daily():
    sed('/etc/logrotate.d/apache2', 'weekly', 'daily', use_sudo=True)

@roles('prx','app','db','munin')
def upgrade_task_manager():
    runcmd('apt-get -y install htop')

@roles('app')
def update_codebetter_git_website():
    update_git_website('codebetter.com',
    'git://github.com/btompkins/CodeBetter.Com-Wordpress.git')

def update_git_website(domain_name, repository_uri):
    with cd('/var/www/{domain}'.format(domain=domain_name)):
        runcmd('git update {repo} master'.format(repo=repository_uri))

@roles('prx','app','db','munin')
def base_host_setup():
    env.user = 'root'    
    #Create local sudoer user, then upgrade Ubuntu.
    prompt('Specify new username: ', 'new_username')
    prompt('Speciry new password: ', 'new_password')
    new_user(env.new_username, env.new_password)
    upgrade_host()

@roles('nginx')
def change_my_password():
    prompt('Specify new password: ', 'new_password')
    runcmd('echo {un}:{pw} | chpasswd'.format(un=env.user, pw=env.new_password))

@roles('nginx')
def deploy_app_servers_nginx():
    prompt('Specify db password: ', 'db_password')  
    install_nginx()
    install_nginx_required_libs()
    get_php_from_source()
    install_git()
    runcmd('mkdir /var/www')
    copy_git_website('codebetter.com',
                     'git://github.com/btompkins/CodeBetter.Com-Wordpress.git',
                     'wp_codebetter',
                     'dbuser',
                     env.db_password,
                     env[env.roledefs['db'][0]])
    configure_nginx_as_upstream_server()
    install_munin_node()
    runcmd('restart munin-node')
    

def configure_nginx_as_upstream_server():
    upload_template('.\\nginx-app\\default.txt', '/etc/nginx/sites-available/default', use_sudo=True)
    sed('/etc/nginx/sites-available/default','IP_ADDRESS', env[env.host_string], use_sudo=True)
    upload_template('.\\nginx-app\\wp-super-cache.conf.txt', '/etc/nginx/wp-super-cache.conf', use_sudo=True)
    upload_template('.\\nginx-app\\nginx.conf.txt', '/etc/nginx/nginx.conf', use_sudo=True)
    upload_template('.\\nginx-app\\php-fpm.conf.txt', '/etc/php/etc/php-fpm.conf', use_sudo=True)
    runcmd('service php-fpm restart')
    runcmd('service nginx restart')
    
def get_php_from_source():
    runcmd('mkdir ~/temp_space')
    with cd('~/temp_space'):
        runcmd('wget http://in3.php.net/get/php-5.3.3.tar.gz/from/us.php.net/mirror')
        runcmd('tar xzvf mirror')
        with cd('php-5.3.3'):
            runcmd('./configure --prefix=/etc/php --with-config-file-path=/etc/php --with-curl --with-pear --with-gd --with-jpeg-dir --with-png-dir --with-zlib --with-xpm-dir --with-freetype-dir --with-t1lib --with-mcrypt --with-mhash --with-mysql --with-mysqli --with-pdo-mysql --with-openssl --with-xmlrpc --with-xsl --with-bz2 --with-gettext --with-fpm-user=www-data --with-fpm-group=www-data --enable-fpm --enable-exif --enable-wddx --enable-zip --enable-bcmath --enable-calendar --enable-ftp --enable-mbstring --enable-soap --enable-sockets --enable-sqlite-utf8 --enable-shmop --enable-dba --enable-sysvmsg --enable-sysvsem --enable-sysvshm')
            runcmd('make && make install')
            runcmd('mkdir /var/log/php-fpm')
            runcmd('chown -R www-data:www-data /var/log/php-fpm')
            runcmd('cp -f php.ini-production /etc/php/php.ini')
            runcmd('chmod 644 /etc/php/php.ini')
            runcmd('cp /etc/php/etc/php-fpm.conf.default /etc/php/etc/php-fpm.conf')
            runcmd('cp -f sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm')
            runcmd('chmod 755 /etc/init.d/php-fpm')
            runcmd('update-rc.d -f php-fpm defaults')         

def install_nginx_required_libs():
    runcmd('apt-get -y install htop binutils cpp flex gcc libarchive-zip-perl libc6-dev libcompress-zlib-perl m4 libpcre3 libpcre3-dev libssl-dev libpopt-dev lynx make perl perl-modules openssl unzip zip autoconf2.13 gnu-standards automake libtool bison build-essential zlib1g-dev ntp ntpdate autotools-dev g++ bc subversion psmisc libmysqlclient-dev libcurl4-openssl-dev libjpeg62-dev libpng3-dev libxpm-dev libfreetype6-dev libt1-dev libmcrypt-dev libxslt1-dev libbz2-dev libxml2-dev libevent-dev libltdl-dev libmagickwand-dev imagemagick')
    
@roles('app')
def deploy_app_servers():
    """
    Deploy apache, mail, ftp, and make apache listen on
    port 8200.  Then deploy our Wordpress install, which
    has already been skinned setup, and stored at github.
    """
    prompt('Specify db password: ', 'db_password')  
    install_apache()
    install_git()
    install_mail()
    install_ftp()    
    setup_website_as_upstream_server('codebetter.com',
                                     '10.180.165.219',
                                     env.roledefs['prx'][0])
    copy_git_website('codebetter.com',
                     'git://github.com/btompkins/CodeBetter.Com-Wordpress.git',
                     'wp_codebetter',
                     'dbuser',
                     env.db_password,
                     env.roledefs['db'][0])
    install_munin_node()
    runcmd('ln -s /usr/share/munin/plugins/apache_accesses /etc/munin/plugins/apache_accesses')
    runcmd('ln -s /usr/share/munin/plugins/apache_processes /etc/munin/plugins/apache_processes')
    runcmd('ln -s /usr/share/munin/plugins/apache_volume /etc/munin/plugins/apache_volume')
    runcmd('restart munin-node')

@roles('prx')
def deploy_reverse_proxy():
    """
    Deploy NGINX and setup as a front end
    reverse proxy, loadbalacing between our app servers.
    """
    install_nginx()
    configure_nginx_proxy()
    configure_nginx_proxy_upstream(env.privateips[env.roledefs['app'][0]])
    configure_nginx_proxy_upstream(env.privateips[env.roledefs['app'][1]])
    install_munin_node()
    runcmd('restart munin-node')
    
@roles('nginx')
def deploy_db_server():
    """
    Setup apache, mysql, and phpmyadmin, git
    and create our databse, and restore from github.
    """
    prompt('Specify db password: ', 'new_password')
    install_apache()
    install_mysql(env.new_password)
    install_phpmyadmin()
    install_git()
    create_database('wp_codebetter',
                    'root',
                    env.new_password,
                    'dbuser',
                    env.new_password)    
    copy_git_database('wp_codebetter',
                      'git://github.com/btompkins/CodeBetter.Com-MySql.git')
    setup_mysql_remote_access('10.180.0.0/16', env.host_string)
    install_munin_node()
    runcmd('ln -s /usr/share/munin/plugins/mysql_bytes /etc/munin/plugins/mysql_bytes')
    runcmd('ln -s /usr/share/munin/plugins/mysql_queries /etc/munin/plugins/mysql_queries')
    runcmd('ln -s /usr/share/munin/plugins/mysql_slowqueries /etc/munin/plugins/mysql_slowqueries')
    runcmd('ln -s /usr/share/munin/plugins/mysql_threads /etc/munin/plugins/mysql_threads')
    runcmd('restart munin-node')

@roles('munin')
def install_munin_server():
    install_nginx()
    runcmd('apt-get -y install munin munin-node munin-plugins-extra')
    sed('/etc/nginx/sites-available/default','usr/share/nginx',
        'var/cache/munin', use_sudo=True)
    sed('/etc/nginx/sites-available/default','localhost',
        'munin.codebetter.com', use_sudo=True)    
    sed('/etc/munin/munin.conf','localhost.localdomain',
        'munin.codebetter.com',use_sudo=True)
    append(['',
            '[nginx.codebetter.com]',
            'address {address}'.format(address=env.roledefs['prx'][0]),
            'use_node_name yes'],
           '/etc/munin/munin.conf', use_sudo=True)           
    append(['',            
            '[app1.codebetter.com]',
            'address {address}'.format(address=env.roledefs['apppriv'][0]),
            ' use_node_name yes'],
           '/etc/munin/munin.conf', use_sudo=True)
    append(['',            
            '[app2.codebetter.com]',
            'address {address}'.format(address=env.roledefs['apppriv'][1]),
            '  use_node_name yes'],
           '/etc/munin/munin.conf', use_sudo=True)
    append(['',            
            '[mysql.codebetter.com]',
            'address {address}'.format(address=env.roledefs['dbpriv'][0]),
            '   use_node_name yes'],
           '/etc/munin/munin.conf', use_sudo=True)

    runcmd('/etc/init.d/nginx restart')

def install_munin_node():
    runcmd('apt-get -y install munin-node munin-plugins-extra libwww-perl')
    append(['host_name {hostname}  # Hostname of the node machine'.format(hostname=env.host_string),
            'allow {mainserver}   # IP address of the central server'.format(mainserver=env.roledefs['munin'][0]),
            'host {hostname}    # Host IP address'.format(hostname=env.host_string)],
            '/etc/munin/munin-node.conf',
           use_sudo=True)
    runcmd('/etc/init.d/munin-node restart')                                                           

           
def new_user(admin_username, admin_password):   
    env.user = 'root'
    
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
    
def upgrade_host():
    runcmd('echo "US/Eastern" | sudo tee /etc/timezone')
    runcmd('dpkg-reconfigure --frontend noninteractive tzdata')
    runcmd('apt-get -y update && apt-get -y dist-upgrade ')

def install_apache():
    runcmd('apt-get -y install apache2 php5 libapache2-mod-php5 mysql-client php5-mysql')
    runcmd('a2enmod rewrite')
    runcmd('a2enmod deflate')
    runcmd('a2enmod expires')
    runcmd('a2enmod headers')
    runcmd('sh -c "echo \'<?php phpinfo( ); ?>\'  > /var/www/info.php"')
    runcmd('/etc/init.d/apache2 restart')    
          
def install_mysql(mysql_root_password):
    runcmd('echo "mysql-server mysql-server/root_password select {password}" |' 
           'debconf-set-selections'.format(
        password=mysql_root_password))
    runcmd('echo "mysql-server mysql-server/root_password_again select ' 
           '{password}" | debconf-set-selections'.format(
        password=mysql_root_password))
    runcmd('apt-get -y install mysql-server')

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
           '\'{user}\'@\'%\' IDENTIFIED BY \'{userpass}\'"'
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
        runcmd('chown mysql *.* -fR')
        
def install_mail():
    runcmd('DEBIAN_FRONTEND=noninteractive apt-get -y install postfix')

def install_ftp():
    runcmd('apt-get -y install vsftpd')
    uncomment('/etc/vsftpd.conf', 'write_enable=YES', use_sudo=True)
    uncomment('/etc/vsftpd.conf', 'local_umask=022', use_sudo=True)   
    uncomment('/etc/vsftpd.conf', 'chroot_local_user=YES', use_sudo=True)
    runcmd('sudo /etc/init.d/vsftpd start')

def setup_website(domain_name):
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

def setup_website_as_upstream_server(domain_name, ip_address, reverse_proxy_ip):
    runcmd('apt-get -y install libapache2-mod-rpaf')
    runcmd('rm /etc/apache2/sites-enabled/000-default')
    upload_template('.\\apache-default-upstream-proxy.txt',
                    '/etc/apache2/sites-enabled/{domain}'.format(
                    domain=domain_name), use_sudo=True)
    sed('/etc/apache2/sites-enabled/{domain}'.format(
        domain=domain_name), 'DOMAIN_NAME', domain_name, use_sudo=True,)
    sed('/etc/apache2/sites-enabled/{domain}'.format(
        domain=domain_name), 'IP_ADDRESS', ip_address, use_sudo=True,)
    sed('/etc/apache2/sites-enabled/{domain}'.format(
        domain=domain_name), 'REVERSE_PROXY_IP', reverse_proxy_ip, use_sudo=True,)
    runcmd('rm /etc/apache2/sites-enabled/*.bak')
    sed('/etc/apache2/apache2.conf', 'MaxClients          150',
        'MaxClients          20',
        use_sudo=True)    
    sed('/etc/apache2/apache2.conf', 'MaxRequestsPerChild   0',
        'MaxRequestsPerChild   2000',
        use_sudo=True)
    sed('/etc/apache2/apache2.conf', 'Timeout 600', 'Timeout 30',
        use_sudo=True)
    append(['',
            '# Customizations',
            'Header unset ETag',
            'ExtendedStatus Off',
            'FileETag None',
            'ExpiresActive On',
            'ExpiresDefault "acc,ess plus 7 days"',
            '<Directory />',
            '   Options FollowSymLinks',
            '</Directory>',
            '<IfModule mod_rewrite.c>',
            '   RewriteLog "/var/log/apache2/rewrite.log"',
            '   RewriteLogLevel 1',
            '   RewriteMap rewritemap txt:/var/www/{domain}/permalinkmap.txt'
            .format(domain=domain_name),
            '   LimitInternalRecursion 5',
            '</IfModule>'], '/etc/apache2/apache2.conf', use_sudo=True)
    comment('/etc/apache2/ports.conf','NameVirtualHost \*:80', use_sudo=True)
    comment('/etc/apache2/ports.conf','Listen 80', use_sudo=True)
    runcmd('/etc/init.d/apache2 restart')


def copy_git_website(domain_name, repository_uri, database_name, database_user, database_password,
                     database_host):
    runcmd('mkdir /var/www/{domain}'.format(domain=domain_name))
    upload_template('.\\nginx-app\\wp-config.php.txt',
                    '/var/www/{domain}/wp-config.php'.format(domain=domain_name),
                    use_sudo=True)    
    with cd('/var/www/{domain}'.format(domain=domain_name)):
        runcmd('git clone {repo} .'.format(repo=repository_uri))
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_NAME', database_name, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_USER', database_user, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_PASSWORD', database_password, use_sudo=True)
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'DATABASE_HOST', database_host, use_sudo=True)        
        sed('/var/www/{domain}/wp-config.php'.format(domain=domain_name),
            'SITE_DOMAIN', domain_name, use_sudo=True)
    with cd('/var/www/'):
        runcmd('chown www-data {domain} -fR'.format(domain=domain_name))

def restart_apache():
        runcmd('/etc/init.d/apache2 restart')


def update_git_website(domain_name, repository_uri):
    with cd('/var/www/{domain}'.format(domain=domain_name)):
        runcmd('git pull {repo} master'.format(repo=repository_uri))
        
def install_nginx():
    runcmd('echo "deb http://ppa.launchpad.net/nginx/stable/ubuntu '
        '$(lsb_release -cs) main" > '
        '/etc/apt/sources.list.d/nginx-stable-$(lsb_release -cs).list')
    runcmd('apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C300EE8C')
    runcmd('apt-get update')
    runcmd('apt-get -y install nginx')

def configure_nginx_proxy():
    upload_template('.\\nginx-default.txt', '/etc/nginx/sites-available/default', use_sudo=True)
    upload_template('.\\permalink.map', '/etc/nginx/sites-available/permalink.map', use_sudo=True)
    
def configure_nginx_proxy_upstream(upstream_server_ip):    
    sed('/etc/nginx/sites-available/default',
        '#NEW_UPSTREAM_SERVER',
        'server {server_ip}:8200 weight=1 fail_timeout=5s;#NEW_UPSTREAM_SERVER'
        .format(server_ip=upstream_server_ip), use_sudo=True)
    runcmd('rm /etc/nginx/sites-available/*.bak')
    runcmd('/etc/init.d/nginx restart')


def setup_mysql_remote_access(remote_range, bind_address):
    comment('/etc/mysql/my.cnf', 'skip-networking', use_sudo=True)
    sed('/etc/mysql/my.cnf', 'bind-address		= 127.0.0.1',
        'bind-address    = {address}'.format(address=bind_address), use_sudo=True)
    runcmd('restart mysql')
    runcmd('iptables -A INPUT -i eth0 -s {remote} -p tcp --destination-port 3306 -j ACCEPT'
           .format(remote=remote_range))
    runcmd('iptables-save')

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
http://danielbachhuber.com/2010/11/29/proxy-caching-wordpress-with-nginx/

"""
