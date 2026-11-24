"""Central filename rules for inventory classification."""

from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True, slots=True)
class ArtifactRule:
    kind: str
    ecosystem: str
    category: str


_EXACT_RULES: dict[str, ArtifactRule] = {
    "package.json": ArtifactRule("package.json", "npm", "manifest"),
    "package-lock.json": ArtifactRule("package-lock.json", "npm", "lockfile"),
    "npm-shrinkwrap.json": ArtifactRule("npm-shrinkwrap.json", "npm", "lockfile"),
    "requirements.txt": ArtifactRule("requirements.txt", "python", "manifest"),
    "pyproject.toml": ArtifactRule("pyproject.toml", "python", "manifest"),
    "setup.cfg": ArtifactRule("setup.cfg", "python", "manifest"),
    "pipfile": ArtifactRule("Pipfile", "python", "manifest"),
    "poetry.lock": ArtifactRule("poetry.lock", "python", "lockfile"),
    "uv.lock": ArtifactRule("uv.lock", "python", "lockfile"),
    "pipfile.lock": ArtifactRule("Pipfile.lock", "python", "lockfile"),
    "pom.xml": ArtifactRule("pom.xml", "maven", "manifest"),
    "build.gradle": ArtifactRule("build.gradle", "gradle", "manifest"),
    "build.gradle.kts": ArtifactRule("build.gradle.kts", "gradle", "manifest"),
    "go.mod": ArtifactRule("go.mod", "go", "manifest"),
    "go.sum": ArtifactRule("go.sum", "go", "lockfile"),
    "cargo.toml": ArtifactRule("Cargo.toml", "cargo", "manifest"),
    "cargo.lock": ArtifactRule("Cargo.lock", "cargo", "lockfile"),
    "gemfile": ArtifactRule("Gemfile", "bundler", "manifest"),
    "gemfile.lock": ArtifactRule("Gemfile.lock", "bundler", "lockfile"),
    "composer.json": ArtifactRule("composer.json", "composer", "manifest"),
    "composer.lock": ArtifactRule("composer.lock", "composer", "lockfile"),
}

_LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".rb": "Ruby",
}


def artifact_rule(relative_path: str) -> ArtifactRule | None:
    """Classify known manifest and lockfile names, preserving case elsewhere."""
    name = PurePosixPath(relative_path).name
    lowered = name.lower()
    if lowered.startswith("requirements-") and lowered.endswith(".txt"):
        return ArtifactRule(name, "python", "manifest")
    return _EXACT_RULES.get(lowered)


def language_for(relative_path: str) -> str | None:
    """Return the source language indicated by a source extension."""
    return _LANGUAGES.get(PurePosixPath(relative_path).suffix.lower())


def is_docker_file(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return (
        name == "dockerfile"
        or name.startswith("dockerfile.")
        or name.endswith(".dockerfile")
        or name in {"compose.yaml", "compose.yml"}
        or (name.startswith("docker-compose") and name.endswith((".yml", ".yaml")))
    )


def is_ci_file(relative_path: str) -> bool:
    parts = PurePosixPath(relative_path).parts
    name = parts[-1].lower()
    lowered_parts = tuple(part.lower() for part in parts)
    return (
        (
            len(parts) >= 3
            and lowered_parts[-3:-1] == (".github", "workflows")
            and name.endswith((".yml", ".yaml"))
        )
        or name == ".gitlab-ci.yml"
        or name == "jenkinsfile"
        or name == "azure-pipelines.yml"
        or (len(parts) >= 2 and lowered_parts[-2:] == (".circleci", "config.yml"))
    )


def is_iac_file(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return (
        name.endswith((".tf", ".tf.json"))
        or name == "terragrunt.hcl"
        or name in {"template.yaml", "template.yml", "cdk.json", "serverless.yml"}
    )


def is_sbom_file(relative_path: str) -> bool:
    name = PurePosixPath(relative_path).name.lower()
    return (
        name in {"bom.json", "bom.xml"}
        or name.endswith((".cdx.json", ".spdx.json"))
        or (name.startswith("sbom") and name.endswith(".json"))
    )


def is_source_directory_name(name: str) -> bool:
    return name.lower() in {"src", "app", "lib"}
