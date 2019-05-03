#! Tracks smtp files

@load base/protocols/smtp

module osquery::download_execution::smtp;

export {

    # SMTP Upload
    type Upload: record {
        to: string &default = "";
        content_type: string &default = "";
        content_disposition: string &default = "";
        file_name: string &default = "";
    };

    type Attachment: record {
        file_id: string;
        file_hash: string;
        file_name: string;
        conn: string &optional;
        to: string &optional;
        content_type: string &optional;
        content_disposition: string &optional;
    };

    # SMTP Attachment
    type Attachment_State: record {
        file_hash: string;
        file_ids: set[string] &default = set();
        tos: set[string] &default = set();
        file_names: set[string] &default = set();
    };

    # Event for received email attachment
    global attachment_added: event(attachment: Attachment);

    # Function to retrieve attachment state for a given hash
    global getAttachmentStateByHash: function(hash: string): set[Attachment_State];
}

# On-going file uploads by session
global current_uploads: table[string] of Upload = table();

# Attachment State by file hash
global attachments: table[string] of Attachment_State = table();

# State freshness by file hash
global freshness: table[string] of bool;

# Sessions and Uploads by file ID
global tracked_file_hashes: table[string] of set[string, Upload] = table();

# Filter of SMTP header names
global ATT_HEADER_NAMES: set[string] = {"TO", "CONTENT-TYPE", "CONTENT-DISPOSITION"};

event osquery::download_execution::smtp::scheduled_remove_hash(hash: string) {
    # Assert
    if (hash !in freshness) {
        print fmt("Unkown hash %s to remove in SMTP attachments", hash);
        return;
    }

    # Was hash seen again since then?
    if (freshness[hash]) {
        freshness[hash] = F;
        # Try later
        schedule 7days { osquery::download_execution::smtp::scheduled_remove_hash(hash) };
        return;
    }

    # Delete hash and freshness
    delete freshness[hash];
    delete attachments[hash];
}

event osquery::download_execution::smtp::attachment_added(attachment: Attachment) {
    # New or existing hash
    local hash = attachment$file_hash;
    local att: Attachment_State;
    if (hash in attachments) {
        att = attachments[hash];
    } else {
        att = [$file_hash = hash];
        att$file_ids = set();
        att$tos = set();
        att$file_names = set();
        attachments[hash] = att;
    }

    # Add to state
    add att$file_ids[attachment$file_id];
    if (attachment?$to) { add att$tos[attachment$to]; }
    if (attachment?$file_name) { add att$file_names[attachment$file_name]; }

    # Schedule Cleanup
    if (hash !in freshness) {
        freshness[hash] = F;
        schedule 7days { osquery::download_execution::smtp::scheduled_remove_hash(hash) };
    } else {
        freshness[hash] = T;
    }
}

function getAttachmentStateByHash(hash: string): set[Attachment_State] {
    if (hash !in attachments) { return set(); }
    return set(attachments[hash]);
}

event mime_one_header(c: connection, h: mime_header_rec) {
    # SMTP only
    if ("SMTP" !in c$service) { return; }
    # Relevant headers only
    if (h$name !in ATT_HEADER_NAMES) { return; }

    # New or update upload
    local upload: Upload;
    if (c$uid in current_uploads) {
        upload = current_uploads[c$uid];
    } else {
        upload = [];
        current_uploads[c$uid] = upload;
    }

    # TO
    if (h$name == "TO") {
        upload$to = h$value;
        upload$content_type = "";
        upload$content_disposition = "";
        upload$file_name = "";
    }
    # CONTENT-TYPE
    if (h$name == "CONTENT-TYPE") {
        local tname_idx = strstr(h$value, ";");
        if (tname_idx != 0) {
            upload$content_type = h$value[:tname_idx-1];
        } else {
            upload$content_type = h$value;
        }
        upload$content_disposition = "";
        upload$file_name = "";
    }
    # CONTENT_DISPOSITION
    if (h$name == "CONTENT-DISPOSITION") {
        # disposition == attachment
        if (strstr(h$value, "attachment") == 1) {
            # disposition name
            local dname_idx = strstr(h$value, ";");
            if (dname_idx != 0) {
                upload$content_disposition = h$value[:dname_idx-1];
            } else {
                upload$content_disposition = h$value;
            }

            # file name
            local fname_idx = strstr(h$value, "filename=");
            if (fname_idx != 0) {
                upload$file_name = h$value[fname_idx+|"filename="|:-1];
            } else {
                upload$file_name = "";
            }
        } else {
            upload$content_disposition = "";
            upload$file_name = "";
        }
    }
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    # Transmitted over any SMTP connections?
    if (f$source != "SMTP") { return; }
    if (!f?$conns) { return; }
    
    # Only for SMTP sessions we registered an attachment for
    local uploads: set[string, Upload] = set();
    local conn: string;
    for (idx in f$conns) {
        # SMTP only
        if ("SMTP" !in f$conns[idx]$service) { next; }
        # Known attachment only
        conn = f$conns[idx]$uid;
        if (conn !in current_uploads) { next; }
        # Candidate upload
        local upload = [$to = current_uploads[conn]$to,
                        $content_type = current_uploads[conn]$to,
                        $content_disposition = current_uploads[conn]$content_disposition,
                        $file_name = current_uploads[conn]$file_name];
        add uploads[f$conns[idx]$uid, upload];
    }
    if (|uploads| == 0) { return; }

    # Require application mime
    if ( !meta?$mime_type || strstr(meta$mime_type, "application") != 1 ) { return; }

    # Remember file ID
    tracked_file_hashes[f$id] = uploads;

    # Calculate MD5
    Files::add_analyzer(f, Files::ANALYZER_MD5);
}

event file_hash(f: fa_file, kind: string, hash: string) {
    # Only hashes for tracked files
    if (f$id !in tracked_file_hashes) { return; }
    # MD5 only
    if (kind != "md5") { return; }
    # Retrieve upload sessions
    local uploads = tracked_file_hashes[f$id];
    delete tracked_file_hashes[f$id];

    # For all uploads
    local attachment: Attachment;
    for ([conn, upload] in uploads) {
        # Merge file upload with hash
        attachment = [
            $file_id = f$id,
            $file_hash = hash,
            $file_name = upload$file_name,
            $conn = conn
        ];
        if (upload$to != "") { attachment$to = upload$to; }
        if (upload$content_type != "") { attachment$content_type = upload$content_type; }
        if (upload$content_disposition != "") { attachment$content_disposition = upload$content_disposition; }

        # Valid file attachment
        event osquery::download_execution::smtp::attachment_added(attachment);
	if ( Cluster::local_node_type() == Cluster::WORKER ) {
		Broker::publish(Cluster::manager_topic, osquery::download_execution::smtp::attachment_added, attachment);
	}
    }
}

event osquery::download_execution::smtp::scheduled_remove_conn(conn: string) {
    # Assert
    if (conn !in current_uploads) {
        print fmt("Unable to remove SMTP uploads for session id %s", conn);
        return;
    }

    delete current_uploads[conn];
}

event connection_state_remove(c: connection) {
    if (c$uid !in current_uploads) { return; }
    schedule 60sec { osquery::download_execution::smtp::scheduled_remove_conn(c$uid) };
}
