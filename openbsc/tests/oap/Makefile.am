AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall -ggdb3 $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS)

EXTRA_DIST = oap_test.ok

if HAVE_LIBGTP
if HAVE_LIBCARES
noinst_PROGRAMS = oap_test
endif
endif

oap_test_SOURCES = oap_test.c

oap_test_LDADD = \
	$(top_builddir)/src/gprs/oap.o \
	$(top_builddir)/src/gprs/oap_messages.o \
	$(top_builddir)/src/gprs/gprs_utils.o \
	$(top_builddir)/src/gprs/gsm_04_08_gprs.o \
	$(top_builddir)/src/libcommon/libcommon.a \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	-lrt

