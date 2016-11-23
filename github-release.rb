require 'octokit'
require 'json'

Octokit.auto_paginate = true

if not ENV['GITHUB_TOKEN']
  puts "Please specify the GITHUB_TOKEN environment variable."
  puts "You can generate one here: https://github.com/settings/tokens/new"
  exit 1
end

client = Octokit::Client.new(:access_token => ENV['GITHUB_TOKEN'])

user = client.user
user.login

repo_name = 'travis-ci/sso'

tags = client.tags(repo_name).map(&:name)
tags = tags.sort_by do |v|
  Gem::Version.new(v.gsub(/^v/, ''))
end
latest = tags.last

releases = client.releases(repo_name).map(&:name)
released = releases.find { |r| r == latest }

if released
  puts "latest tags has a release attached!"
  puts "(if you want to make a new release, make a new tag first!)"
  puts "(current latest tag is #{latest})"
  exit 0
end

while true
  print "creating release for tag #{latest}, confirm [y/n] "
  input = gets.strip
  case
  when input == "y"
    break
  when input == "n"
    puts "okay, aborting"
    exit 1
  else
    puts "please enter y or n"
  end
end

release = client.create_release(repo_name, latest, {
  name: latest,
  prerelease: true,
})
client.upload_asset(release.url, 'build/linux/amd64/sso', {
  content_type: "application/octet-stream",
})

puts "✅  done!"
