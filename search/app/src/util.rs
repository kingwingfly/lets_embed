pub fn encode_path(path: &str) -> String {
    path.split('/')
        .map(|seg| urlencoding::encode(seg).into_owned())
        .collect::<Vec<_>>()
        .join("/")
}
