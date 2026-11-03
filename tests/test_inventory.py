from pathlib import Path

from vulnguard.inventory import (
    collect_docker,
    collect_fixture,
    parse_banners,
    parse_go_mod,
    parse_package_json,
    parse_pom,
    parse_remote_inventory,
    parse_requirements,
)

ROOT = Path(__file__).resolve().parents[1]


def test_fixture_merges_debian_redis_and_reads_manifests():
    assets, warnings, host = collect_fixture(ROOT / "demo" / "lab")
    assert warnings == []
    assert host == "moshi-lab-01"
    by_name = {asset.name: asset for asset in assets}
    assert by_name["nginx"].version == "1.18.0"
    assert by_name["nginx"].exposure == "internet"
    assert by_name["redis"].ecosystem == "Debian"
    assert by_name["redis"].version == "5:5.0.7-2+deb10u1"
    assert by_name["mysql"].version == "5.7.41"
    assert by_name["pyyaml"].version == "5.3.1"
    assert by_name["jinja2"].ecosystem == "PyPI"
    assert by_name["lodash"].version == "4.17.20"
    assert by_name["org.apache.logging.log4j:log4j-core"].version == "2.14.1"
    assert by_name["gopkg.in/yaml.v3"].ecosystem == "Go"
    assert "bash" in by_name


def test_parsers_ignore_unpinned_and_comments():
    req = parse_requirements("# comment\nFlask\nrequests>=2\nPyYAML==5.3.1\n", "t", "requirements.txt")
    assert [asset.name for asset in req] == ["pyyaml"]
    package = parse_package_json('{"dependencies": {"minimist": "^1.2.5", "left-pad": "github:x/y"}}', "t", "p")
    assert package[0].version == "1.2.5"
    assert len(package) == 1
    pom = parse_pom(
        "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>${log4j.version}</version></dependency>"
        "<dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
        "<version>2.14.1</version></dependency></dependencies></project>",
        "t",
        "pom",
    )
    assert len(pom) == 1
    go = parse_go_mod("module example.com/a\n\ngo 1.20\n\nrequire (\n\tgopkg.in/yaml.v3 v3.0.0\n)\n", "t", "go")
    assert go[0].version == "v3.0.0"


def test_banners_and_remote_sections():
    banners = parse_banners("nginx version: nginx/1.18.0\nRedis server v=5.0.7 sha=abc bits=64\n", "local")
    assert {item.name for item in banners} == {"nginx", "redis"}
    remote = """===DPKG===
redis-server\t5:5.0.7-2+deb10u1
===NGINX===
nginx version: nginx/1.18.0
===REDIS===
Redis server v=5.0.7 sha=abc bits=64
===MYSQL===
mysql  Ver 14.14 Distrib 5.7.41, for Linux (x86_64)
===END===
"""
    assets = parse_remote_inventory(remote, "ssh:demo")
    redis = next(item for item in assets if item.name == "redis")
    assert redis.ecosystem == "Debian"


def test_docker_runner_parses_exec_output():
    outputs = {
        ("docker", "ps"): "abc\tedge-nginx\tnginx:1.18.0\n",
        ("docker", "exec", "abc", "nginx", "-v"): "nginx version: nginx/1.18.0\n",
        ("docker", "exec", "abc", "redis-server", "--version"): "",
        ("docker", "exec", "abc", "mysql", "--version"): "",
        ("docker", "exec", "abc", "mysqld", "--version"): "",
        ("docker", "exec", "abc", "dpkg-query"): "",
        ("docker", "exec", "abc", "cat", "/opt/app/requirements.txt"): "PyYAML==5.3.1\n",
        ("docker", "exec", "abc", "cat", "/opt/app/package.json"): "{}\n",
        ("docker", "exec", "abc", "cat", "/opt/app/pom.xml"): "<project></project>\n",
        ("docker", "exec", "abc", "cat", "/opt/app/go.mod"): "module example.com/a\n\ngo 1.22\n",
    }

    def runner(argv):
        if tuple(argv[:2]) == ("docker", "ps"):
            return 0, outputs[("docker", "ps")], ""
        key = tuple(argv)
        if key in outputs:
            return 0, outputs[key], ""
        if argv[:3] == ["docker", "exec", "abc"] and argv[3] == "cat":
            return 0, outputs.get(tuple(argv), ""), ""
        return 1, "", "missing"

    assets, warnings, host = collect_docker(runner)
    assert host == "docker"
    names = {asset.name for asset in assets}
    assert "nginx" in names
    assert "pyyaml" in names
    assert warnings == []
