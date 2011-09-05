package LdapTools;
use strict;
use warnings;

use Carp;
use Net::LDAP;

# use Data::Dumper;
use PasswordTools;

#----------------------------------------------------
# params:
# host=>'localhost'     LDAP host
# port=> '389'          LDAP port
# user=>'user',         Bind dn
# password=>'pass',     LDAP dn password
# tls=>'no',            Enable or disable tls (yes|no)
# basedn=>'dc=local'    Base search
#----------------------------------------------------
sub new {
    my $self = shift;
    bless
        exists $_[0] ? exists $_[1] ? {@_} : { %{ $_[0] } } : {},
        ref $self || $self;
}

#connect ldap
# $ldap->connect();
sub _connect {
    my ($self) = @_;
    my $ldap = undef;

    if ( $self->{tls} eq 'yes' ) {
        eval {
            $ldap = Net::LDAP->new(
                'ldaps://' . $self->{host} . ':' . $self->{port},
                verify  => 'none',
                timeout => 3
            ) or croak "$@";
        };
    }
    else {
        eval { $ldap = Net::LDAP->new( 'ldap://' . $self->{host} . ':' . $self->{port}, timeout => 3 ) or croak "$@"; };
    }
    if ( defined $ldap ) {
        $ldap->bind( $self->{user}, password => $self->{password} );

    }

    if ( defined $ldap ) {
        $self->{ldap} = $ldap;
        return 0;
    }
    else {
        return 1;
    }

}

# disconnect ldap
# $ldap->disconnect();
sub _disconnect {
    my ($self) = @_;
    my $ldap = $self->{ldap};

    $ldap->unbind;
}

# sub reconnect {
#     my ($self) = @_;
#     if (defined $self->{ldap}) {
#         $self->connect_ldap();
#         $self->disconnect();
#     } else {
#         $self->connect_ldap();
#     }
# }

#ldap search
#my $result = $ldap->search(
#   "dc=ru",'(objectclass=top)','search','sub', ['uid','cn','uidnumber']
#   )
# return Array
sub search {
    my ( $self, $base_dn, $filter, $deref, $scope, $attrs, $array_attrs ) = @_;

    if ( ! $self->_connect() ) {
        my $ldap = $self->{ldap};

        my $ldap_res = $ldap->search(
            base   => $base_dn,
            filter => $filter,
            deref  => $deref,
            scope  => 'sub',
            attrs  => $attrs,
        );

        my $href = $ldap_res->as_struct();

        $self->_disconnect();
        return _hashToArray( $self, $href, $attrs, $array_attrs );
    }
    else {
        return ();
    }

}

#convert ldap hash to array
sub _hashToArray {
    my ( $self, $href, $attrs, $array_attrs ) = @_;
    my @result_array;
    my @arrayOfDNs = keys %$href;

    foreach my $dn (@arrayOfDNs) {
        my $valref = $$href{$dn};
        my $tmp_hash_ref->{'dn'} = $dn;
        foreach my $attr (@$attrs) {  
            my $attr_lc = lc $attr;
            if ( defined $$valref{$attr_lc} ) {
                if ( grep { $_ eq $attr } @$array_attrs ) {
                    $tmp_hash_ref->{$attr} = $$valref{$attr_lc};
                }
                else {
                    $tmp_hash_ref->{$attr} = $$valref{$attr_lc}->[0];
                }
            }
            else {
                $tmp_hash_ref->{$attr} = "None";
            }
        }
        push( @result_array, $tmp_hash_ref );
    }
    return @result_array;
}

sub ldapReplace {
    my ( $self, $dn, $whatToChange ) = @_;
    $self->_connect();
    my $ldap = $self->{ldap};
    my $result = $ldap->modify( $dn, changes => [ replace => [@$whatToChange] ] );

    $self->_disconnect();

    return $result;
}

sub ldapCreate {
    my ( $self, $dn, $whatToCreate ) = @_;
    $self->_connect();
    my $ldap = $self->{ldap};
    my $result = $ldap->add( $dn, attrs => [@$whatToCreate] );

    $self->_disconnect();
    return $result;
}

sub ldapDelete {

}

1;
