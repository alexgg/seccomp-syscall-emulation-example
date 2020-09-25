FILE=seccomp-test

all:
	@gcc ${FILE}.c -o ${FILE} -lseccomp -I usr/include && ./${FILE};

clean:
	@rm -rf ${FILE}

