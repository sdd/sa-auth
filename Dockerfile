FROM lambci/lambda:build-provided.al2
COPY setup-rust-image.sh .
RUN ./setup-rust-image.sh