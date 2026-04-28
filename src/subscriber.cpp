#include "../include/dlads/alert_event.hpp"
#include <zmq.hpp>
#include <iostream>
#include <string>

int main() {
    zmq::context_t ctx(1);
    zmq::socket_t  sub(ctx, zmq::socket_type::sub);

    sub.connect("tcp://localhost:5555");
    sub.set(zmq::sockopt::subscribe, "");

    std::cout << "[dlads] coordinator subscriber listening on port 5555\n";

    while (true) {
        zmq::message_t msg;
        sub.recv(msg, zmq::recv_flags::none);

        std::string_view raw(static_cast<char*>(msg.data()), msg.size());

        auto result = dlads::deserialize(raw);

        if (!result.has_value()) {
            std::cerr << "[warn] deserialization failed, raw: " << raw << "\n";
            continue;
        }

        const auto& alert = result.value();

        std::cout << "\n[ALERT]"
                  << "\n  id:          " << alert.alert_id
                  << "\n  host:        " << alert.source_host
                  << "\n  rule:        " << alert.rule_id
                  << "\n  severity:    " << dlads::to_string(alert.severity)
                  << "\n  score:       " << alert.anomaly_score
                  << "\n  description: " << alert.description;

        if (alert.metadata.count("source_ip"))
            std::cout << "\n  source_ip:   " << alert.metadata.at("source_ip");

        if (alert.metadata.count("z_score"))
            std::cout << "\n  z_score:     " << alert.metadata.at("z_score");

        std::cout << "\n";
    }
}