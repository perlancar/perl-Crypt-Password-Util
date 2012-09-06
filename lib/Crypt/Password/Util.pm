package Crypt::Password::Util;

use 5.010;
use strict;
use warnings;

# VERSION

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(looks_like_crypt);

my $b64d = qr![A-Za-z0-9./]!;

sub looks_like_crypt {
    my ($str) = @_;
    $str =~ m#\A(?:
                  (?: \$ (?:apr)?1 \$ $b64d {0,8} \$ $b64d {22} ) |
                  (?: \$ 6         \$ $b64d {0,8} \$ $b64d {86} )
              )\z#sx;
}

1;
# ABSTRACT: Crypt password utilities

=head1 SYNOPSIS

 use Crypt::Password::Util qw(looks_like_crypt);

 say looks_like_crypt('$1$$...');               # 1
 say looks_like_crypt('$apr1$4DdvgCFk$...');    # 1
 say looks_like_crypt('$6$4DdvgCFk$...');       # 1
 say looks_like_crypt('foo');                   # 0


=head1 FUNCTIONS

=head2 looks_like_crypt($str) => BOOL

Return true if C<$str> looks like a crypted password.

=cut
