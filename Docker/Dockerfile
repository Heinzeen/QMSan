FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

#Install the dependencies
RUN apt update
RUN apt install -y git python3 python-is-python3 pkg-config libglib2.0-dev libpixman-1-dev make valgrind
RUN apt install -y lld llvm llvm-dev clang

RUN mkdir /root/sanitizers/
RUN mkdir /root/AFLpp/
RUN mkdir /root/tests/

WORKDIR /root/sanitizers/
#clone QMSan and create both the accurate and the opportunistic detectors
RUN git clone https://github.com/Heinzeen/QMSan.git opportunistic
RUN git clone https://github.com/Heinzeen/QMSan.git accurate

#build both detectors
RUN cd opportunistic/ && python build.py --msan --no_lib --afl
RUN cd accurate/ && python build.py --msan --taint

WORKDIR /root/AFLpp/
#clone our custom implementation of AFL++
RUN git clone https://github.com/Heinzeen/AFL-QMSan.git
RUN cd AFL-QMSan && CFLAGS="-DQMSAN_DEBUG -DQMSAN -DQMSAN_CALLSTACK -DQMSAN_CALLSTACK_EDGES -DQMSAN_FILTERING -DQMSAN_EDGES" make clean all

#a bunch of env variables for AFL++
ENV AFL_SKIP_CPUFREQ=1
ENV AFL_NO_AFFINITY=1

#comment this if you want to use valgrind as accurate detector
ENV QMSAN_PATH=/root/sanitizers/accurate/qmsan

WORKDIR /root/tests/
#setup fuzzing env
RUN mkdir in
#empty seed
RUN echo "hi" > in/in
