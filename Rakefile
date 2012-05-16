WORKSPACE    = "braintree-ios-encryption.xcodeproj/project.xcworkspace/"
SDK          = "iphonesimulator4.3"
TEST_SCHEME  = "test"
BUILD_SCHEME = "braintree-encryption"

task :default => "test:unit"

namespace :test do
  task :unit do
    begin
      start_simulator
      xcode_build("Debug", TEST_SCHEME)
    rescue
    ensure
      kill_simulator
    end
  end
end

task :build => ["build:debug"]

task :release => ["build:release", "release:archive"]

namespace :release do
  task :archive do
    version = File.read('src/BraintreeEncryption.m')[/VERSION = @"(.*)";/, 1]
    puts version

    target_filename = "BraintreeEncryption-#{version}"
    puts target_filename

    FileUtils.mkdir_p("products/archive/")

    Dir.chdir("products/BraintreeEncryption") do
      sh "tar cf #{target_filename}.tar --exclude='*.tar' ."
      sh "gzip #{target_filename}.tar"
      FileUtils.mv("./#{target_filename}.tar.gz", "../../products/archive/")
    end
  end
end

namespace :build do
  task :debug do
    xcode_build("Debug", BUILD_SCHEME)
  end

  task :release do
    xcode_build("Release", BUILD_SCHEME)
    FileUtils.mkdir_p("products/BraintreeEncryption")
    sh "cp -r products/Release-universal/ products/BraintreeEncryption"
  end

  task :clean do
    xcode_build("Debug", BUILD_SCHEME, false)
  end
end

def start_simulator
  Kernel.system "open /Developer/Platforms/iPhoneSimulator.platform/Developer/Applications/iPhone\\ Simulator.app"
end

def kill_simulator
  Kernel.system "killall -9 iPhone\\ Simulator"
end

def xcode_build(config, scheme, build=true)
  Kernel.system "xcodebuild -workspace #{WORKSPACE} -scheme #{scheme} -sdk #{SDK} -configuration #{config} clean #{build ? "build" : "" }"
end

task :remove_trailing_whitespace do
  Dir.glob("test").each do |file_path|
    sh %Q{find src test -name "*.[h,m]" -type f -print0 | xargs -0 sed -i '' -E "s/[[:space:]]*$//"}
  end
end

