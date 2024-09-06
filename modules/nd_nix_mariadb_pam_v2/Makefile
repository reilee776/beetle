CC=gcc
CFLAGS=-fPIC -O2 -c -g -Wall -Wformat-security -fno-strict-aliasing
LDFLAGS=--shared `mysql_config --libs`
DESTDIR=

all: nd_nix_mariadb_pam_v2.so

nd_nix_mariadb_pam_v2.so: nd_nix_mariadb_pam_v2.o
	$(LD) $(LDFLAGS) -o nd_nix_mariadb_pam_v2.so nd_nix_mariadb_pam_v2.o

clean:
	$(RM) *.so *.o

install: nd_nix_mariadb_pam_v2.so
	install -D -m 0755 nd_nix_mariadb_pam_v2.so $(DESTDIR)/usr/lib64/security/nd_nix_mariadb_pam_v2.so

