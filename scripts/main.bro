#! Detects execution of downloaded files.

@load zeek-osquery-framework
@load zeek-osquery-state

module osquery::download_execution;

export {
    # Event for the execution of file attachments transmitted by smtp
    global smtp_attachment_execution: event(host_id: string, file_hash: string, tos: set[string], file_names: set[string]);
}

# Hash values of binary paths for each host
global binary_hashes: table[string] of table[string] of string;

event osquery::download_execution::delete_binary_hash(host_id: string, path: string) {
    if (host_id !in binary_hashes) { return; }
    if (path !in binary_hashes[host_id]) { return; }
    delete binary_hashes[host_id][path];
}

event osquery::download_execution::process_binary_hash(resultInfo: osquery::ResultInfo, path: string, md5: string) {
    local host_id = resultInfo$host;
    
    # Update Cache
    if (host_id !in binary_hashes) { binary_hashes[host_id] = table(); }
    if (path !in binary_hashes[host_id]) { 
        binary_hashes[host_id][path] = md5;
        schedule 90sec { osquery::download_execution::delete_binary_hash(host_id, path) };
    }

    # Known smtp attachment hash
    local smtp_attachments = osquery::download_execution::smtp::getAttachmentStateByHash(md5);
    for (smtp_att in smtp_attachments) {
        event osquery::download_execution::smtp_attachment_execution(host_id, md5, smtp_att$tos, smtp_att$file_names);
    }
}

event osquery::process_state_added(host_id: string, process_info: osquery::ProcessInfo) {
    # Binaries only
    if (!process_info?$path || process_info$path == "") { return; }

    # Cached
    if (host_id in binary_hashes && process_info$path in binary_hashes[host_id]) {
        local resultInfo: osquery::ResultInfo = [$host=host_id, $utype=osquery::SNAPSHOT];
        event osquery::download_execution::process_binary_hash(resultInfo, process_info$path, binary_hashes[host_id][process_info$path]);
        return;
    }
    
    # Select query
    local query_string = fmt("SELECT path, md5 FROM hash WHERE path=\"%s\"", process_info$path);

    # Send query
    local query = [$ev=osquery::download_execution::process_binary_hash, $query=query_string];
    osquery::execute(query, host_id);

}
