FROM rust 
RUN apt-get update && apt-get install -y curl jq 
WORKDIR /opacity-simple-prover
COPY . .
RUN cargo build --release
COPY /target/release/prover /usr/bin/prover
COPY run_prover.sh /opacity-simple-prover/run_prover.sh
ENTRYPOINT ["chmod +x /opacity-simple-prover/run_prover.sh && /opacity-simple-prover/run_prover.sh"]