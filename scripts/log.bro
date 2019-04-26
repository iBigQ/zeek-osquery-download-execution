#! Logs the execution of downloaded files.

module osquery::logging::download_execution;

export {
	# Logging
    redef enum Log::ID += { LOG };

    type Info: record {
        host_id: string &log;
        file_hash: string &log;
        tos: set[string] &optional &log;
        file_names: set[string] &optional &log;
    };
}

event osquery::download_execution::smtp_attachment_execution(host_id: string, file_hash: string, tos: set[string], file_names: set[string]) {
    local info: Info = [
        $host_id = host_id,
        $file_hash = file_hash
    ];
    if (|tos| != 0) { info$tos = tos; }
    if (|file_names| != 0) { info$file_names = file_names; }

    Log::write(LOG, info);
}

event bro_init() {
    Log::create_stream(LOG, [$columns=Info, $path="osq-smtp-execution"]);
}
