CC       ?= gcc
CFLAGS   ?= -Wall -Wextra -O2

TARGET   := sentinel
SOURCE   := sentinel.c

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc
UNITDIR  ?= /etc/systemd/system

CONFIG   := etc/sentinel.conf
SERVICE  := etc/systemd/system/sentinel.service

INSTALL  ?= install

.PHONY: all clean install install-config install-service

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

install: all
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

install-config:
	$(INSTALL) -m 0644 -D $(CONFIG) $(DESTDIR)$(SYSCONFDIR)/sentinel.conf

install-service:
	$(INSTALL) -m 0644 -D $(SERVICE) $(DESTDIR)$(UNITDIR)/sentinel.service
