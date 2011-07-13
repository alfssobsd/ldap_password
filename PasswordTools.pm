package PasswordTools;

use strict;
use warnings;

use Digest::SHA1;
use Digest::MD5;
use MIME::Base64;

sub new {
    my $self = shift;
    bless
        exists $_[0] ? exists $_[1] ? {@_} : { %{ $_[0] } } : {},
        ref $self || $self;
}

# Crypt Password
sub cryptPassword {
    my ( $self, $schema, $clear_password ) = @_;

    if ( $schema eq 'crypt' ) {
        return $self->genCRYPT($clear_password);
    }

    if ( $schema eq 'ssha' ) {
        return $self->genSSHA($clear_password);
    }

    if ( $schema eq 'md5' ) {
        return $self->genMD5($clear_password);
    }

    return 0;
}

#Check Password
sub checkPassword {
    my ( $self, $schema, $password, $clear_password ) = @_;

    if ( $schema eq 'crypt' ) {
        if (crypt( $clear_password, substr( $password, 7 ) ) eq
            substr( $password, 7 ) )
        {
            return 1;
        }
    }

    if ( $schema eq 'ssha' ) {
        my $decode_password = decode_base64( substr( $password, 6 ) );
        my $digest = substr( $decode_password, 0, 20 );
        my $salt   = substr( $decode_password, 20 );
        my $ctx    = Digest::SHA1->new;
        $ctx->add($clear_password);
        $ctx->add($salt);
        if ( $ctx->digest eq $digest ) {
            return 1;
        }
    }

    if ( $schema eq 'md5' ) {
        my $salt = '';
        $salt = $self->{salt} if defined $self->{salt};
        my $ctx = Digest::MD5->new;
        $ctx->add($clear_password);
        $ctx->add($salt);
        if ( encode_base64( $ctx->digest . $salt, '' ) eq
            substr( $password, 5 ) )
        {
            return 1;
        }
    }

    return 0;
}

#Generate crypt password
sub genCRYPT {
    my ( $self, $password ) = @_;

    my $salt = randomSalt(8);
    $salt = $self->{salt} if defined $self->{salt};
    my $hash = "{CRYPT}" . crypt( $password, $salt );

    return $hash;
}

#Generate md5 password
sub genMD5 {
    my ( $self, $password ) = @_;

    my $salt = '';
    $salt = $self->{salt} if defined $self->{salt};
    my $ctx = Digest::MD5->new;
    $ctx->add($password);
    $ctx->add($salt);
    my $hash = "{MD5}" . encode_base64( $ctx->digest . $salt, '' );

    return $hash;
}

#Generate ssha password
sub genSSHA {
    my ( $self, $password ) = @_;

    my $salt = randomSalt(4);
    $salt = $self->{salt} if defined $self->{salt};
    my $ctx = Digest::SHA1->new;
    $ctx->add($password);
    $ctx->add($salt);
    my $hash = "{SSHA}" . encode_base64( $ctx->digest . $salt, '' );

    return $hash;
}

#Generate random salt
sub randomSalt {
    my ($length) = @_;
    my @tab = ( '.', '/', 0 .. 9, 'A' .. 'Z', 'a' .. 'z' );
    return join "", @tab[ map { rand 64 } ( 1 .. $length ) ];
}

1;
