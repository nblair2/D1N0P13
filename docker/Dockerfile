FROM python:3

# Install Tools
RUN apt-get update && \
    apt-get install -qq -y \
    build-essential \
    findutils \
    libasio-dev \
    zip \
    unzip \
    git \
    cmake \
    bridge-utils \
    net-tools \
    iptables \
    iproute2 \
    iputils-ping \
    traceroute \
    tcpdump \
    libnetfilter-queue-dev \
    libpcap-dev \
    && apt-get clean

# Install python packages
WORKDIR /root/
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install DNP3-demo
RUN cd /usr/local/src && \
    git clone --recursive https://github.com/sintax1/dnp3.git

RUN cd /usr/local/src/dnp3 && \
    cmake -DDNP3_DEMO=true . && \
    make

RUN cd /usr/local/src/dnp3 && \
    cp outstation-demo /bin/DNP3-outstation-demo && \
    cp master-demo /bin/DNP3-master-demo
