#! Logs the smtp files.

module osquery::logging::download_execution::smtp;

export {
	# Logging
    redef enum Log::ID += { LOG };

    type Info: record {
        file_id: string &log;
        file_hash: string &log;
        file_name: string &log;
        conn: string &optional &log;
        to: string &optional &log;
        content_type: string &optional &log;
        content_disposition: string &optional &log;
    };
}

event osquery::download_execution::smtp::attachment_recved(attachment: osquery::download_execution::smtp::Attachment) {
    local info: Info = [
        $file_id = attachment$file_id,
        $file_hash = attachment$file_hash,
        $file_name = attachment$file_name
    ];
    if (attachment?$conn) { info$conn = attachment$conn; }
    if (attachment?$to) { info$to = attachment$to; }
    if (attachment?$content_type) { info$content_type = attachment$content_type; }
    if (attachment?$content_disposition) { info$content_disposition = attachment$content_disposition; }

    Log::write(LOG, info);
}

event bro_init() {
    Log::create_stream(LOG, [$columns=Info, $path="osq-smtp-attachment"]);
}
