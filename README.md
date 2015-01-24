<<<<<<< HEAD
**SYNOPSIS**
=======
# SYNOPSIS
>>>>>>> master

    use Crypt::Password::Util qw(crypt_type looks_like_crypt crypt);

    say crypt_type('62F4a6/89.12z');                    # CRYPT
    say crypt_type('$1$$...');                          # MD5-CRYPT
    say crypt_type('$apr1$4DdvgCFk$...');               # MD5-CRYPT
    say crypt_type('$5$4DdvgCFk$...');                  # SSHA256
    say crypt_type('$6$4DdvgCFk$...');                  # SSHA512
    say crypt_type('1a1dc91c907325c69271ddf0c944bc72'); # PLAIN-MD5
    say crypt_type('foo');                              # undef

    say looks_like_crypt('62F4a6/89.12z');   # 1
    say looks_like_crypt('foo');             # 0

    say crypt('pass'); # automatically choose the appropriate type and salt

<<<<<<< HEAD
**FUNCTIONS**

    crypt_type($str) => STR
Return crypt type, or undef if $str does not look like a crypted password.  Currently known types: CRYPT (traditional DES crypt), MD5-CRYPT (including Apache variant), SSHA256 (salted SHA256), SSHA512 (salted SHA512), and PLAIN-MD5.

    looks_like_crypt($str) => BOOL
Return true if $str looks like a crypted password.


    crypt($str) => STR
Like Perl's crypt(), but automatically choose the appropriate crypt type and random salt. Will first choose SSHA512 with 64-bit random salt. If not supported by system, fall back to MD5-CRYPT with 32-bit random salt. If that is not supported, fall back to CRYPT.

**SEE ALSO**

Authen::Passphrase which recognizes more encodings (but currently not SSHA256 and SSHA512).

=======
# FUNCTIONS

## crypt\_type($str) => STR

Return crypt type, or undef if `$str` does not look like a crypted password.
Currently known types: CRYPT (traditional DES crypt), MD5-CRYPT (including
Apache variant), SSHA256 (salted SHA256), SSHA512 (salted SHA512), and
PLAIN-MD5.

## looks\_like\_crypt($str) => BOOL

Return true if `$str` looks like a crypted password.

## crypt($str) => STR

Like Perl's crypt(), but automatically choose the appropriate crypt type and
random salt. Will first choose SSHA512 with 64-bit random salt. If not supported
by system, fall back to MD5-CRYPT with 32-bit random salt. If that is not
supported, fall back to CRYPT.

# SEE ALSO

[Authen::Passphrase](https://metacpan.org/pod/Authen::Passphrase) which recognizes more encodings (but currently not SSHA256
and SSHA512).
>>>>>>> master
