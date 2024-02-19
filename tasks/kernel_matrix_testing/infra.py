import json
import os

from tasks.kernel_matrix_testing.kmt_os import get_kmt_os
from tasks.kernel_matrix_testing.stacks import ask_for_ssh, find_ssh_key
from tasks.kernel_matrix_testing.tool import Exit, error


class LocalCommandRunner:
    @staticmethod
    def run_cmd(ctx, _, cmd, allow_fail, verbose):
        res = ctx.run(cmd.format(proxy_cmd=""), hide=(not verbose), warn=allow_fail)
        if not res.ok:
            error(f"[-] Failed: {cmd}")
            if allow_fail:
                return False
            print_failed(res.stderr)
            raise Exit("command failed")

        return True

    @staticmethod
    def move_to_shared_directory(ctx, _, source, subdir=None):
        recursive = ""
        if os.path.isdir(source):
            recursive = "-R"

        full_target = get_kmt_os().shared_dir
        if subdir is not None:
            full_target = os.path.join(get_kmt_os().shared_dir, subdir)
            ctx.run(f"mkdir -p {full_target}")
        ctx.run(f"cp {recursive} {source} {full_target}")


class RemoteCommandRunner:
    @staticmethod
    def run_cmd(ctx, instance, cmd, allow_fail, verbose):
        res = ctx.run(
            cmd.format(
                proxy_cmd=f"-o ProxyCommand='ssh -o StrictHostKeyChecking=no -i {instance.ssh_key} -W %h:%p ubuntu@{instance.ip}'"
            ),
            hide=(not verbose),
            warn=allow_fail,
        )
        if not res.ok:
            error(f"[-] Failed: {cmd}")
            if allow_fail:
                return False
            print_failed(res.stderr)
            raise Exit("command failed")

        return True

    @staticmethod
    def move_to_shared_directory(ctx, instance, source, subdir=None):
        full_target = get_kmt_os().shared_dir
        if subdir is not None:
            full_target = os.path.join(get_kmt_os().shared_dir, subdir)
            self.run_cmd(ctx, instance, f"mkdir -p {full_target}", False, False)

        ctx.run(
            f"rsync -e \"ssh -o StrictHostKeyChecking=no -i {instance.ssh_key}\" -p -rt --exclude='.git*' --filter=':- .gitignore' {source} ubuntu@{instance.ip}:{full_target}"
        )


def get_instance_runner(arch):
    if arch == "local":
        return LocalCommandRunner
    else:
        return RemoteCommandRunner


def print_failed(output):
    out = list()
    for line in output.split("\n"):
        out.append(f"\t{line}")
    error('\n'.join(out))


class LibvirtDomain:
    def __init__(self, ip, domain_id, tag, vmset_tags, ssh_key_path, instance):
        self.ip = ip
        self.name = domain_id
        self.tag = tag
        self.vmset_tags = vmset_tags
        self.ssh_key = ssh_key_path
        self.instance = instance

    def run_cmd(self, ctx, cmd, allow_fail=False, verbose=False):
        run = f"ssh -o StrictHostKeyChecking=no -i {self.ssh_key} root@{self.ip} {{proxy_cmd}} '{cmd}'"
        return self.instance.runner.run_cmd(ctx, self.instance, run, allow_fail, verbose)

    def copy(self, ctx, source, target):
        run = f"rsync -e \"ssh -o StrictHostKeyChecking=no {{proxy_cmd}} -i {self.ssh_key}\" -p -rt --exclude='.git*' --filter=':- .gitignore' {source} root@{self.ip}:{target}"
        return self.instance.runner.run_cmd(ctx, self.instance, run, False, False)

    def __repr__(self):
        return f"<LibvirtDomain> {self.name} {self.ip}"

    def get_libvirt_object(self, conn):
        for domain in conn.listAllDomains():
            if domain.name().endswith(self.name):
                return domain

        return None


class HostInstance:
    def __init__(self, ip: str, arch: str, ssh_key):
        self.ip = ip
        self.arch = arch
        self.ssh_key = ssh_key
        self.microvms: list[LibvirtDomain] = []
        self.runner = get_instance_runner(arch)

    def add_microvm(self, domain: LibvirtDomain):
        self.microvms.append(domain)

    def copy_to_all_vms(self, ctx, path, subdir=None):
        self.runner.move_to_shared_directory(ctx, self, path, subdir)

    def __repr__(self):
        return f"<HostInstance> {self.ip} {self.arch}"


def build_infrastructure(stack: str, remote_ssh_key=None):
    stack_outputs = os.path.join(get_kmt_os().stacks_dir, stack, "stack.output")
    with open(stack_outputs, 'r') as f:
        infra_map = json.load(f)

    infra: dict[str, HostInstance] = dict()
    for arch in infra_map:
        if arch != "local" and remote_ssh_key is None:
            if ask_for_ssh():
                raise Exit("No ssh key provided. Pass with '--ssh-key=<key-name>'")

        key = None
        if remote_ssh_key is not None:
            key = ssh_key_to_path(remote_ssh_key)
        instance = HostInstance(infra_map[arch]["ip"], arch, key)
        for vm in infra_map[arch]["microvms"]:
            instance.add_microvm(
                LibvirtDomain(vm["ip"], vm["id"], vm["tag"], vm["vmset-tags"], vm["ssh-key-path"], instance)
            )

        infra[arch] = instance

    return infra


def ssh_key_to_path(ssh_key):
    ssh_key_path = ""
    if ssh_key != "":
        ssh_key.rstrip(".pem")
        ssh_key_path = find_ssh_key(ssh_key)

    return ssh_key_path
