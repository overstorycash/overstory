fn main() -> anyhow::Result<()> {
    proto::run(std::env::args().skip(1).collect())
}
