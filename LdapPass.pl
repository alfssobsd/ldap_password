#!/usr/bin/env perl

use Mojolicious::Lite;
use PasswordTools;
use Net::LDAP;
#use Data::Dumper;

# Documentation browser under "/perldoc" (this plugin requires Perl 5.10)
#plugin 'pod_renderer';

any '/index' => sub {
    my $self   = shift;
    my $method = $self->req->method;

    my $host_ldap     = "ldap.example.ru";
    my $bind_dn       = "cn=admin,dc=example,dc=ru";
    my $bind_password = 'password';
    my $search_base   = "ou=people,dc=example,dc=ru";
    my $schema_pass   = "ssha";

    if ( $method eq 'POST' ) {
        my $userLogin   = $self->param('login');
        my $oldPassword = $self->param('oldpass');
        my $newPassword = $self->param('newpass');
		$userLogin =~ s/[&,|\\\/= ]//g;
		#$self->app->log->debug($userLogin);
		
        my $pass = PasswordTools->new();

        my $ldap = Net::LDAP->new($host_ldap) or exit 1;
        my $mesg = $ldap->bind( $bind_dn, password => $bind_password );
        $mesg = $ldap->search(
            base   => $search_base,
            filter => "(uid=$userLogin)",
            attrs  => ['userPassword']
        );

        if ( $mesg->count ) {
            my $entry           = $mesg->entry(0);
            my $currentPassword = $entry->get_value('userPassword');
            my $currentDn       = 'uid=' . $userLogin . ',' . $search_base;
            #$self->app->log->debug($currentPassword);
            #$self->app->log->debug($currentDn);

            if ( $pass->checkPassword( $schema_pass, $currentPassword, $oldPassword ) ) {
                if ( length($newPassword) > 5 ) {
                    my $tmpCryptPass = $pass->cryptPassword( $schema_pass, $newPassword );
                    $mesg = $ldap->modify( $currentDn,
                        replace => { 'userPassword' => $tmpCryptPass } );
                    $self->render('done');
                }
            }
        }
    }

    $self->render('index');
};

app->mode('production');
app->secret('sdkfjhskjd');
app->start;
__DATA__

@@ index.html.ep
% layout 'default';
% title 'Change password';
<%= form_for index =>(method => 'post') =>  begin %>
Login:<br>
<%= text_field 'login' %><br>
Old password:<br>
<%= password_field 'oldpass' %><br>
New password:<br>
<%= password_field 'newpass' %><br>
<p style="color: #808080; font-size: 10px;">The password will be longer than 5 characters.</p>
<%= submit_button 'Change password' %>
<% end %>

@@ done.html.ep
% layout 'default';
% title 'Success Change password';
<h1>password changed</h1>

@@ layouts/default.html.ep
<!doctype html>
<html>
	<head><title><%= title %></title>
		<style type="text/css">
		.main_block {
		  width : 100%;
		  text-align : center;
		}
		.center_block {
		  width : 200px;
		  margin : 0 auto;
		}
		</style>
  	</head>
	<body>	
		<div class="main_block">
	 		<div class="center_block">
				<%= content %>
			</div>
		</div>
	</body>
</html>

