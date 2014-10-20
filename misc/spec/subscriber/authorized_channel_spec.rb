# encoding: ascii
require 'spec_helper'
require 'openssl'

describe "Create authorized channel" do
  let(:config) do
    {
      :header_template => nil,
      :footer_template => nil,
      :message_template => '~text~',
      :subscriber_mode => subscriber_mode,
      :authorized_channels_only => 'on',
      :authorize_key => 'test_key',
      :subscriber_connection_ttl => "1s"
    }
  end

  shared_examples_for "can create auhtorized channel" do
    it "should reject not authorized channel" do
      channel = 'ch_test_create_authroized_channel_not_authorized_'

      nginx_run_server(config) do |conf|
        EventMachine.run do
          unsigned_channel = channel + conf.subscriber_mode

          sub = EventMachine::HttpRequest.new(nginx_address + '/sub/' + unsigned_channel.to_s).get :head => headers
          sub.callback do
            sub.should be_http_status(403).without_body
            sub.response_header['X_NGINX_PUSHSTREAM_EXPLAIN'].should eql("Subscriber could not create channels.")
            EventMachine.stop
          end
        end
      end  
    end

    it "should reject expired authorized channel" do
      channel = 'ch_test_create_authroized_channel_expired_'

      nginx_run_server(config) do |conf|
        EventMachine.run do
          unsigned_channel = channel + conf.subscriber_mode
          signed_channel = sign_channel(unsigned_channel, Time.now.to_i - 10, conf.authorize_key)

          sub = EventMachine::HttpRequest.new(nginx_address + '/sub/' + signed_channel.to_s).get :head => headers
          sub.callback do
            sub.should be_http_status(403).without_body
            sub.response_header['X_NGINX_PUSHSTREAM_EXPLAIN'].should eql("Subscriber could not create channels.")
            EventMachine.stop
          end
        end
      end  
    end

    it "should reject invalid authorized channel" do
      channel = 'ch_test_create_authroized_channel_expired_'
      key = 'invalid'

      nginx_run_server(config) do |conf|
        EventMachine.run do
          unsigned_channel = channel + conf.subscriber_mode
          signed_channel = sign_channel(unsigned_channel, Time.now.to_i + 1000, key)

          sub = EventMachine::HttpRequest.new(nginx_address + '/sub/' + signed_channel.to_s).get :head => headers
          sub.callback do
            sub.should be_http_status(403).without_body
            sub.response_header['X_NGINX_PUSHSTREAM_EXPLAIN'].should eql("Subscriber could not create channels.")
            EventMachine.stop
          end
        end
      end  
    end

    it "should create authorized channel" do
      channel = 'ch_test_create_authroized_channel_authorized_'

      nginx_run_server(config) do |conf|
        EventMachine.run do
          unsigned_channel = channel + conf.subscriber_mode
          signed_channel = sign_channel(unsigned_channel, Time.now.to_i + 1000, conf.authorize_key)

          sub = EventMachine::HttpRequest.new(nginx_address + '/sub/' + signed_channel.to_s).get :head => headers
          sub.callback do
            check_created(sub)
            EventMachine.stop
          end
        end
      end  
    end
  end

  def sign_channel(channel, expires, secret)
      unsigned_value = "#{channel}.a#{expires}"
      return "#{unsigned_value}.#{OpenSSL::HMAC.hexdigest('sha1', secret, unsigned_value)}"
    end

  def check_created(sub)
    sub.should be_http_status(304).without_body
  end

  context "in stream mode" do
    let(:subscriber_mode) { "streaming" }

    def check_created(sub)
      sub.should be_http_status(200).without_body
    end

    it_should_behave_like "can create auhtorized channel"
  end

  context "in pooling mode" do
    let(:subscriber_mode) { "polling" }

    it_should_behave_like "can create auhtorized channel"
  end

  context "in long-pooling mode" do
    let(:subscriber_mode) { "long-polling" }

    it_should_behave_like "can create auhtorized channel"
  end

  context "in event source mode" do
    let(:subscriber_mode) { "eventsource" }

    def check_created(sub)
      sub.should be_http_status(200).without_body
    end

    it_should_behave_like "can create auhtorized channel"
  end
end
