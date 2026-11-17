from .devices import Device, DeviceRepo


class UnknownTarget(Exception):
    pass


class NoDevices(Exception):
    pass


def _group_members(repo: DeviceRepo, target: str) -> list[Device]:
    t = target.lower()
    return [d for d in repo.list() if t in (g.lower() for g in d.groups)]


def resolve_targets(repo: DeviceRepo, target: str) -> list[Device]:
    dev = repo.get(target)
    if dev is not None:
        return [dev]
    if target.lower() == "all":
        eligible = [d for d in repo.list() if not d.is_self]
        if not eligible:
            raise NoDevices("no eligible devices")
        return eligible
    members = _group_members(repo, target)
    if not members:
        raise UnknownTarget(target)
    return members


def is_bulk(target: str, repo: DeviceRepo) -> bool:
    if repo.get(target) is not None:
        return False
    if target.lower() == "all":
        return True
    return len(_group_members(repo, target)) > 1
