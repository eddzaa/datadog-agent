import sys

from invoke.context import Context

from tasks.kernel_matrix_testing.tool import info
from tasks.kernel_matrix_testing.vars import Arch, arch_mapping


class CompilerImage:
    def __init__(self, ctx: Context, arch: Arch):
        self.ctx = ctx
        self.arch: Arch = arch

    @property
    def name(self):
        return f"kmt-compiler-{self.arch}"

    @property
    def image(self):
        return f"kmt:compile-{self.arch}"

    @property
    def is_built(self):
        res = self.ctx.run(f"docker images {self.image} | grep -v REPOSITORY | grep kmt", warn=True)
        return res is not None and res.ok

    def ensure_built(self):
        if not self.is_built:
            info(f"[*] Compiler image for {self.arch} not built, building it...")
            self.build()

    @property
    def is_running(self):
        res = self.ctx.run(f"docker ps -aqf \"name={self.name}\"", hide=True)
        if res is not None and res.ok:
            return res.stdout.rstrip() != ""
        return False

    def ensure_running(self):
        if not self.is_running:
            info(f"[*] Compiler for {self.arch} not running, starting it...")
            self.start()

    def exec(self, cmd, user="compiler", verbose=True, run_dir=None):
        if run_dir:
            cmd = f"cd {run_dir} && {cmd}"

        self.ensure_running()
        return self.ctx.run(f"docker exec -u {user} -i {self.name} bash -c \"{cmd}\"", hide=(not verbose))

    def build(self):
        self.ctx.run(f"docker rm -f $(docker ps -aqf \"name={self.name}\")", warn=True, hide=True)
        self.ctx.run(f"docker image rm {self.image}", warn=True, hide=True)

        if self.arch == "x86_64":
            docker_platform = "linux/amd64"
            buildimages_arch = "x64"
        else:
            docker_platform = "linux/arm64"
            buildimages_arch = "arm64"

        docker_build_args = ["--platform", docker_platform]

        # Add build arguments (such as go version) from go.env
        with open("../datadog-agent-buildimages/go.env", "r") as f:
            for line in f:
                docker_build_args += ["--build-arg", line.strip()]

        docker_build_args_s = " ".join(docker_build_args)
        self.ctx.run(
            f"cd ../datadog-agent-buildimages && docker build {docker_build_args_s} -f system-probe_{buildimages_arch}/Dockerfile -t {self.image} ."
        )

    def stop(self):
        self.ctx.run(f"docker rm -f $(docker ps -aqf \"name={self.name}\")")

    def start(self):
        self.ensure_built()

        if self.is_running:
            self.stop()

        self.ctx.run(
            f"docker run -d --restart always --name {self.name} --mount type=bind,source=./,target=/datadog-agent {self.image} sleep \"infinity\""
        )

        uid = self.ctx.run("id -u").stdout.rstrip()
        gid = self.ctx.run("id -g").stdout.rstrip()
        self.exec(f"getent group {gid} || groupadd -f -g {gid} compiler", user="root")
        self.exec(f"getent passwd {uid} || useradd -m -u {uid} -g {gid} compiler", user="root")

        if sys.platform != "darwin":  # No need to change permissions in MacOS
            self.exec(f"chown {uid}:{gid} /datadog-agent && chown -R {uid}:{gid} /datadog-agent", user="root")

        self.exec("apt install sudo", user="root")
        self.exec("usermod -aG sudo compiler && echo 'compiler ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers", user="root")
        self.exec("echo conda activate ddpy3 >> /home/compiler/.bashrc", user="compiler")
        self.exec(f"install -d -m 0777 -o {uid} -g {uid} /go", user="root")


def get_compiler(ctx: Context, arch: Arch):
    return CompilerImage(ctx, arch)


def all_compilers(ctx: Context):
    return [get_compiler(ctx, arch) for arch in arch_mapping.values()]
