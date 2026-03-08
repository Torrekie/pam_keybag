PROJECT= pam_keybag
MODULE_NAME?= pam_keybag
HELPER_NAME?= pam_keybag_helper

SRCDIR?= src
INCLUDEDIR?= include
BUILDDIR?= build
ENTDIR?= entitlements

ROOTLESS?= 0
.if ${ROOTLESS} != "0"
ROOT_PREFIX?= /var/jb
.else
ROOT_PREFIX?=
.endif

PREFIX?= ${ROOT_PREFIX}/usr
PAM_MODULE_DIR?= ${PREFIX}/lib/pam
LIBEXEC_DIR?= ${PREFIX}/libexec
MANDIR?= ${PREFIX}/share/man/man8

XCRUN_PATH!= command -v xcrun 2>/dev/null || true
.if !empty(XCRUN_PATH)
CC?= ${XCRUN_PATH} --sdk iphoneos clang
OBJC?= ${XCRUN_PATH} --sdk iphoneos clang
.else
CC?= clang
OBJC?= clang
.endif
INSTALL?= install

CFLAGS+= -O2 -Wall -Wextra
OBJCFLAGS+= -O2 -Wall -Wextra -fobjc-arc
MODULE_CFLAGS+= -fPIC -fno-common
MODULE_OBJCFLAGS+= -fobjc-arc
HELPER_CFLAGS+=
ROOT_PREFIX_DEFINE= -DPAM_KEYBAG_ROOT_PREFIX=\"${ROOT_PREFIX}\"

PAM_INCLUDE_DIR?= ${ROOT_PREFIX}/usr/include
PAM_LIB_DIR?= ${ROOT_PREFIX}/usr/lib
TARGET?= arm64-apple-ios14.0

.if defined(TARGET) && !empty(TARGET)
TARGET_FLAG= -target ${TARGET}
.else
TARGET_FLAG=
.endif

MODULE_SRCS= ${SRCDIR}/pam_keybag.c ${SRCDIR}/pam_keybag_core.m
HELPER_SRC= ${SRCDIR}/pam_keybag_helper.m
MODULE_SO= ${BUILDDIR}/${MODULE_NAME}.2.so
HELPER_BIN= ${BUILDDIR}/${HELPER_NAME}
UI_HELPER_DEFAULT_PATH= ${ROOT_PREFIX}/usr/libexec/pam_keybag_helper
MODULE_DEFAULT_PATH= ${ROOT_PREFIX}/usr/lib/pam/pam_keybag.2.so
MANPAGE_NAME= pam_keybag.8
MANPAGE_TEMPLATE= ${MANPAGE_NAME}.in
MANPAGE= ${BUILDDIR}/${MANPAGE_NAME}

MODULE_LIBS?= -lpam -framework CoreFoundation -framework Foundation -framework LocalAuthentication
HELPER_LIBS?= -framework Foundation

HELPER_ENT?= ${ENTDIR}/helper.ent.plist

.PHONY: all clean install uninstall sign print-vars

all: ${MODULE_SO} ${HELPER_BIN} ${MANPAGE}

${MODULE_SO}: ${MODULE_SRCS} ${INCLUDEDIR}/Logging.h ${INCLUDEDIR}/pam_keybag_core.h
	@mkdir -p ${BUILDDIR}
	${CC} ${TARGET_FLAG} ${CFLAGS} ${MODULE_CFLAGS} ${MODULE_OBJCFLAGS} \
		${ROOT_PREFIX_DEFINE} \
		-I${INCLUDEDIR} -I${PAM_INCLUDE_DIR} \
		-bundle -undefined dynamic_lookup -L${PAM_LIB_DIR} \
		-o ${MODULE_SO} ${MODULE_SRCS} ${MODULE_LIBS}

${HELPER_BIN}: ${HELPER_SRC} ${INCLUDEDIR}/pam_keybag_core.h
	@mkdir -p ${BUILDDIR}
	${OBJC} ${TARGET_FLAG} ${OBJCFLAGS} ${HELPER_CFLAGS} \
		${ROOT_PREFIX_DEFINE} \
		-I${INCLUDEDIR} \
		-o ${HELPER_BIN} ${HELPER_SRC} ${HELPER_LIBS}

${MANPAGE}: ${MANPAGE_TEMPLATE}
	@mkdir -p ${BUILDDIR}
	sed \
		-e 's|@UI_HELPER_DEFAULT_PATH@|${UI_HELPER_DEFAULT_PATH}|g' \
		-e 's|@MODULE_DEFAULT_PATH@|${MODULE_DEFAULT_PATH}|g' \
		${MANPAGE_TEMPLATE} > ${MANPAGE}

sign: all
	ldid -S ${MODULE_SO}

	@if [ -f "${HELPER_ENT}" ]; then \
		ldid -S${HELPER_ENT} ${HELPER_BIN}; \
	else \
		echo "warning: ${HELPER_ENT} not found, skipping helper signing"; \
	fi

install: all
	${INSTALL} -d ${DESTDIR}${PAM_MODULE_DIR} ${DESTDIR}${LIBEXEC_DIR} ${DESTDIR}${MANDIR}
	${INSTALL} -m 755 ${MODULE_SO} ${DESTDIR}${PAM_MODULE_DIR}/${MODULE_NAME}.2.so
	ln -sf ${MODULE_NAME}.2.so ${DESTDIR}${PAM_MODULE_DIR}/${MODULE_NAME}.so
	${INSTALL} -m 755 ${HELPER_BIN} ${DESTDIR}${LIBEXEC_DIR}/${HELPER_NAME}
	${INSTALL} -m 644 ${MANPAGE} ${DESTDIR}${MANDIR}/${MANPAGE_NAME}

uninstall:
	rm -f ${DESTDIR}${PAM_MODULE_DIR}/${MODULE_NAME}.so
	rm -f ${DESTDIR}${PAM_MODULE_DIR}/${MODULE_NAME}.2.so
	rm -f ${DESTDIR}${LIBEXEC_DIR}/${HELPER_NAME}
	rm -f ${DESTDIR}${MANDIR}/${MANPAGE_NAME}

clean:
	rm -rf ${BUILDDIR}

print-vars:
	@echo "ROOTLESS=${ROOTLESS}"
	@echo "ROOT_PREFIX=${ROOT_PREFIX}"
	@echo "XCRUN_PATH=${XCRUN_PATH}"
	@echo "CC=${CC}"
	@echo "OBJC=${OBJC}"
	@echo "MODULE_SO=${MODULE_SO}"
	@echo "HELPER_BIN=${HELPER_BIN}"
	@echo "PAM_MODULE_DIR=${PAM_MODULE_DIR}"
	@echo "LIBEXEC_DIR=${LIBEXEC_DIR}"
	@echo "UI_HELPER_DEFAULT_PATH=${UI_HELPER_DEFAULT_PATH}"
	@echo "MODULE_DEFAULT_PATH=${MODULE_DEFAULT_PATH}"
	@echo "MANPAGE=${MANPAGE}"
	@echo "TARGET=${TARGET}"
