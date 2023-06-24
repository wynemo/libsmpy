from lpenz/debian-bookworm-mips64el as builder

WORKDIR /

run apt-get update
# run apt-get upgrade -y 
# install rust
run apt-get install -y curl
run curl https://sh.rustup.rs -sSf | sh -s -- -y
# install python
run apt-get install -y wget build-essential libreadline-dev libssl-dev libsqlite3-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev
run wget https://www.python.org/ftp/python/3.8.11/Python-3.8.11.tgz
run tar zxf Python-3.8.11.tgz
run cd Python-3.8.11 && ./configure --enable-optimizations && make && make install
run python3.8 -m venv venv
run /venv/bin/python -m pip install maturin
run /venv/bin/maturin build
