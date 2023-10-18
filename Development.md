# E3DB-Core
Software Development Kit (SDK) for interacting with Tozny products and services from C software environments AND a Command Line Interface for shell environments.

# Development


## Build

```bash
make build
```


# Publishing

## Versioning

Follow [semantic versioning](https://semver.org) when releasing new versions of this library.

Releasing involves tagging a commit in this repository, and pushing the tag. Tagging and releasing of new versions should only be done from the master branch after an approved Pull Request has been merged, or on the branch of an approved Pull Request.

To publish a new version, run

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```
