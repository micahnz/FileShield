.PHONY: all clean install test bench lint

CC      := gcc
CFLAGS  := -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 \
           -fstack-protector-strong -fstack-clash-protection \
           -Wformat-security -D_FORTIFY_SOURCE=2 -fPIE \
           -D_DEFAULT_SOURCE -D_GNU_SOURCE
LDFLAGS := -Wl,-z,relro -Wl,-z,now -pie

SRCDIR  := src
OBJDIR  := build
TSTDIR  := tests
BINDIR  := /usr/local/sbin
ETCDIR  := /etc
SYSDDIR := /etc/systemd/system

TARGET  := fileshield

SRCS    := $(SRCDIR)/main.c $(SRCDIR)/utils.c $(SRCDIR)/config.c \
           $(SRCDIR)/cache.c $(SRCDIR)/session.c $(SRCDIR)/notify.c \
           $(SRCDIR)/fanotify.c $(SRCDIR)/inode.c $(SRCDIR)/sha512.c \
           $(SRCDIR)/persist.c
OBJS    := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS    := $(OBJS:.o=.d)

TESTS   := test_cache test_config test_utils test_persist test_session test_sha512 test_inode test_fanotify
TSTBINS := $(TESTS:%=$(OBJDIR)/%)

all: $(OBJDIR)/$(TARGET)

$(OBJDIR)/$(TARGET): $(OBJS)
	@mkdir -p $(OBJDIR)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

-include $(DEPS)

$(OBJDIR)/test_cache: $(OBJDIR)/cache.o $(OBJDIR)/utils.o $(TSTDIR)/test_cache.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_cache.c $(OBJDIR)/cache.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_config: $(OBJDIR)/config.o $(OBJDIR)/utils.o $(TSTDIR)/test_config.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_config.c $(OBJDIR)/config.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_utils: $(OBJDIR)/utils.o $(TSTDIR)/test_utils.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_utils.c $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_session: $(OBJDIR)/session.o $(OBJDIR)/utils.o $(TSTDIR)/test_session.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_session.c $(OBJDIR)/session.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_sha512: $(OBJDIR)/sha512.o $(OBJDIR)/utils.o $(TSTDIR)/test_sha512.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_sha512.c $(OBJDIR)/sha512.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_persist: $(OBJDIR)/persist.o $(OBJDIR)/utils.o $(TSTDIR)/test_persist.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_persist.c $(OBJDIR)/persist.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_inode: $(OBJDIR)/inode.o $(OBJDIR)/utils.o $(TSTDIR)/test_inode.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_inode.c $(OBJDIR)/inode.o $(OBJDIR)/utils.o -o $@

# Links the full event pipeline: fanotify.o needs notify/config/cache/
# session/sha512/persist/utils, and the test supplies the daemon's signal
# globals.
$(OBJDIR)/test_fanotify: $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
                         $(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
                         $(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
                         $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
		$(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
		$(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
		$(OBJDIR)/utils.o -o $@

test: all $(TSTBINS)
	@failed=0; \
	for t in $(TSTBINS); do \
		echo "=== $$t ==="; \
		$$t || failed=1; \
	done; \
	if [ $$failed -eq 1 ]; then \
		echo "FAIL"; \
		exit 1; \
	else \
		echo "PASS"; \
	fi

# Hot-path microbenchmarks (not part of `make test`): timing baselines
# for the optimization work live in the commit messages and in comments
# at the changed sites.  Needs the same objects as the daemon.
$(OBJDIR)/bench_hotpath: $(TSTDIR)/bench_hotpath.c $(OBJDIR)/fanotify.o \
                         $(OBJDIR)/notify.o $(OBJDIR)/config.o \
                         $(OBJDIR)/cache.o $(OBJDIR)/session.o \
                         $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
                         $(OBJDIR)/inode.o $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/bench_hotpath.c $(OBJDIR)/fanotify.o \
		$(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
		$(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
		$(OBJDIR)/inode.o $(OBJDIR)/utils.o -o $@

bench: all $(OBJDIR)/bench_hotpath
	./$(OBJDIR)/bench_hotpath

install: all
	install -m 0755 -D $(OBJDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -m 0640 -D fileshield.conf $(DESTDIR)$(ETCDIR)/fileshield.conf
	install -m 0644 -D fileshield.service $(DESTDIR)$(SYSDDIR)/fileshield.service
	systemctl daemon-reload
	sudo systemctl restart fileshield
clean:
	rm -rf $(OBJDIR)

lint:
	cppcheck --std=c99 --enable=all --suppress=missingIncludeSystem \
		--suppress=unusedFunction --suppress=checkersReport \
		$(SRCDIR)/*.c $(TSTDIR)/*.c 2>&1 || true

debug: CFLAGS += -O0 -g -U_FORTIFY_SOURCE -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all
