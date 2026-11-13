# Homebrew formula for Sift.
#
# Maintained automatically by GoReleaser (`brews` section of .goreleaser.yaml)
# after every release. This checked-in copy is the fallback / template for the
# very first formula, before any release has been published.
#
# Test with:   brew tap asadbekabdulboqiyev/tap && brew install Sift
class Sift < Formula
  desc "Distributed load testing and network simulator written in Go"
  homepage "https://github.com/asadbekabdulboqiyev/sift"
  url "https://github.com/asadbekabdulboqiyev/sift/releases/download/v0.14.14/Sift_0.14.14_darwin_arm64.tar.gz"
  version "0.14.14"
  license "Apache-2.0"
  head "https://github.com/asadbekabdulboqiyev/sift.git", branch: "main"

  # Pure Go: no system dependencies, no libpcap.
  def install
    bin.install "Sift"
  end

  def caveats
    <<~EOS
      Sift needs elevated file-descriptor limits to reach high
      virtual-user counts. macOS caps these per process; raise them with:

        sudo sysctl -w kern.maxfiles=1048576

      On Linux, use the systemd unit instead:
        LimitNOFILE=1048576
    EOS
  end

  test do
    assert_match "distributed load", shell_output("#{bin}/Sift --help")
    assert_match version.to_s, shell_output("#{bin}/Sift version")
  end
end
