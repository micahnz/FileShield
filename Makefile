.PHONY: all clean install install-config uninstall test bench lint

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

# `make install` never replaces an existing /etc/fileshield.conf (upgrades
# keep local rules). Set REPLACE_CONFIG=1, or run `make install-config`,
# to overwrite it with the shipped defaults.
# With DESTDIR set (packaging), systemctl is skipped entirely.  Otherwise the
# unit is reloaded and an already-running service is restarted with the new
# binary (try-restart keeps a stopped service stopped).
REPLACE_CONFIG ?= 0

SRCS    := $(SRCDIR)/main.c $(SRCDIR)/utils.c $(SRCDIR)/config.c \
           $(SRCDIR)/cache.c $(SRCDIR)/session.c $(SRCDIR)/notify.c \
           $(SRCDIR)/fanotify.c $(SRCDIR)/inode.c $(SRCDIR)/sha512.c \
           $(SRCDIR)/persist.c $(SRCDIR)/pin.c $(SRCDIR)/reload.c
OBJS    := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS    := $(OBJS:.o=.d)

TESTS   := test_cache test_config test_reload test_utils test_persist test_pin test_session test_sha512 test_inode test_fanotify
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

$(OBJDIR)/test_pin: $(OBJDIR)/pin.o $(OBJDIR)/persist.o $(OBJDIR)/utils.o $(TSTDIR)/test_pin.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_pin.c $(OBJDIR)/pin.o $(OBJDIR)/persist.o $(OBJDIR)/utils.o -o $@

$(OBJDIR)/test_inode: $(OBJDIR)/inode.o $(OBJDIR)/utils.o $(TSTDIR)/test_inode.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_inode.c $(OBJDIR)/inode.o $(OBJDIR)/utils.o -o $@

# Links the full event pipeline: fanotify.o needs notify/config/cache/
# session/sha512/persist/utils, and the test supplies the daemon's signal
# globals.
$(OBJDIR)/test_fanotify: $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
                         $(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
                         $(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
                         $(OBJDIR)/pin.o $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_fanotify.c $(OBJDIR)/fanotify.o $(OBJDIR)/notify.o \
		$(OBJDIR)/config.o $(OBJDIR)/cache.o $(OBJDIR)/session.o \
		$(OBJDIR)/sha512.o $(OBJDIR)/persist.o $(OBJDIR)/inode.o \
		$(OBJDIR)/pin.o $(OBJDIR)/utils.o -o $@

# Links the reload decision path with fan_fd = -1: every kernel mark fails,
# so parse failure, reject plus rollback, and rollback failure are exercised
# without privileges.
$(OBJDIR)/test_reload: $(TSTDIR)/test_reload.c $(OBJDIR)/reload.o $(OBJDIR)/fanotify.o \
                       $(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
                       $(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
                       $(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/test_reload.c $(OBJDIR)/reload.o $(OBJDIR)/fanotify.o \
		$(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
		$(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
		$(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/utils.o -o $@

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
                         $(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/utils.o
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) $(TSTDIR)/bench_hotpath.c $(OBJDIR)/fanotify.o \
		$(OBJDIR)/notify.o $(OBJDIR)/config.o $(OBJDIR)/cache.o \
		$(OBJDIR)/session.o $(OBJDIR)/sha512.o $(OBJDIR)/persist.o \
		$(OBJDIR)/inode.o $(OBJDIR)/pin.o $(OBJDIR)/utils.o -o $@

bench: all $(OBJDIR)/bench_hotpath
	./$(OBJDIR)/bench_hotpath

install: all
	install -m 0755 -D $(OBJDIR)/$(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@if [ "$(REPLACE_CONFIG)" = "1" ]; then \
		install -m 0640 -D fileshield.conf "$(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "installed default config (overwrote $(DESTDIR)$(ETCDIR)/fileshield.conf)"; \
	elif [ -e "$(DESTDIR)$(ETCDIR)/fileshield.conf" ]; then \
		echo "keeping existing $(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "  (set REPLACE_CONFIG=1 to overwrite it with the shipped defaults)"; \
	else \
		install -m 0640 -D fileshield.conf "$(DESTDIR)$(ETCDIR)/fileshield.conf"; \
		echo "installed default config to $(DESTDIR)$(ETCDIR)/fileshield.conf"; \
	fi
	install -m 0644 -D fileshield.service "$(DESTDIR)$(SYSDDIR)/fileshield.service"
	@if [ -z "$(DESTDIR)" ]; then \
		systemctl daemon-reload; \
		if [ "$$(id -u)" -eq 0 ]; then \
			systemctl try-restart fileshield; \
		else \
			sudo systemctl try-restart fileshield; \
		fi; \
	else \
		echo "staged install ($(DESTDIR)): skipping systemctl"; \
	fi

# Convenience alias for `make install REPLACE_CONFIG=1`.
install-config:
	$(MAKE) install REPLACE_CONFIG=1

# Remove the installed binary and unit.  Never touches /etc/fileshield.conf
# or the state and pins under /var/lib/fileshield.
uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(SYSDDIR)/fileshield.service"
	@if [ -z "$(DESTDIR)" ]; then systemctl daemon-reload; fi
	@echo "removed $(DESTDIR)$(BINDIR)/$(TARGET) and $(DESTDIR)$(SYSDDIR)/fileshield.service"
	@echo "left /etc/fileshield.conf and /var/lib/fileshield untouched"

clean:
	rm -rf $(OBJDIR)

lint:
	cppcheck --std=c99 --enable=all --suppress=missingIncludeSystem \
		--suppress=unusedFunction --suppress=checkersReport \
		--suppress=normalCheckLevelMaxBranches \
		--suppress=unmatchedSuppression \
		--suppress=variableScope --suppress=constVariablePointer \
		--suppress=constParameterCallback \
		--error-exitcode=1 $(SRCDIR)/*.c $(TSTDIR)/*.c

debug: CFLAGS += -O0 -g -U_FORTIFY_SOURCE -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: clean all
