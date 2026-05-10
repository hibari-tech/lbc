//! LBC Control Plane binary entrypoint.

fn main() -> anyhow::Result<()> {
    control_plane::run()
}
