FROM rust 
COPY /target/release/prover /usr/bin/prover
RUN apt-get update && apt-get install -y curl jq 
WORKDIR /opacity-simple-prover
COPY run_prover.sh /opacity-simple-prover/run_prover.sh
RUN chmod +x /opacity-simple-prover/run_prover.sh
ENTRYPOINT ["/opacity-simple-prover/run_prover.sh"]