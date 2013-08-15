
MODULE_big = uuid-freebsd
OBJS = uuid-freebsd.o
DATA_built = uuid-freebsd.sql
DATA = uninstall_uuid-freebsd.sql
SHLIB_LINK = -lmd

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

