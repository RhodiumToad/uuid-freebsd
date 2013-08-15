
EXTENSION = uuid-freebsd
DATA = uuid-freebsd--2.0.sql
MODULE_big = uuid-freebsd
OBJS = uuid-freebsd.o
SHLIB_LINK = -lmd

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

