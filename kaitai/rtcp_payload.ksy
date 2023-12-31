meta:
  id: rtcp_payload
  title: rtcp network payload (single udp packet)
  xref:
    justsolve: RTP
    wikidata: Q749940
  license: CC0-1.0
  ks-version: 0.7
  endian: be

doc: RTCP is the Real-Time Control Protocol

doc-ref: https://www.rfc-editor.org/rfc/rfc3550

seq:
  - id: rtcp_packets
    type: rtcp_packet
    repeat: eos

types:
  rtcp_packet:
    seq:
      - id: version
        type: b2
      - id: padding
        type: b1
      - id: subtype
        type: b5
      - id: type
        type: u1
        enum: packet_type
      - id: length
        type: u2
      - id: data
        size: 4 * length
        type:
          switch-on: type
          cases:
            'packet_type::sr': sr_packet
            'packet_type::rr': rr_packet
            'packet_type::sdes': sdes_packet
            'packet_type::bye': bye_packet
            'packet_type::psfb': psfb_packet
            'packet_type::rtpfb': rtpfb_packet

  sr_packet:
    seq:
      - id: sneder_ssrc
        type: u4
      - id: ntp_msw
        type: u4
      - id: ntp_lsw
        type: u4
      - id: rtp_timestamp
        type: u4
      - id: sender_packet_count
        type: u4
      - id: sender_octet_count
        type: u4
      - id: report_blocks
        type: report_block
        repeat: expr
        repeat-expr: _parent.subtype
    instances:
      ntp:
        value: (ntp_msw << 32) & ntp_lsw

  rr_packet:
    seq:
      - id: sneder_ssrc
        type: u4
      - id: report_blocks
        type: report_block
        repeat: expr
        repeat-expr: _parent.subtype

  report_block:
    seq:
      - id: ssrc_identifier
        type: u4
      - id: fraction_lost
        type: u1
      - id: cumulative_number_of_packets_lost 
        size: 3
      - id: extended_highest_sequence_number_received  
        type: u4
      - id: interarrival_jitter 
        type: u4
      - id: last_sr
        type: u4
      - id: delay_since_last_sr
        type: u4

  sdes_packet:
    seq:
      - id: chunks
        type: sdes_chunk
        repeat: expr
        repeat-expr: num_chunks
    instances:
      num_chunks:
        value: _parent.subtype

  sdes_chunk:
    seq:
      - id: ssrc
        type: u4
      - id: items
        type: sdes_item
        repeat: eos
  
  sdes_item:
    seq:
      - id: type
        type: u1
        enum: sdes_item_type
      - id: len_value
        type: u1
        if: type != sdes_item_type::end
      - id: value
        size: len_value
        if: type != sdes_item_type::end

  rtpfb_packet:
    seq:
      - id: ssrc
        type: u4
      - id: ssrc_media_source
        type: u4
      - id: fci_block
        type:
          switch-on: fmt
          cases:
            'rtpfb_subtype::transport_feedback': rtpfb_transport_feedback_packet
        size-eos: true
    instances:
      fmt:
        value: _parent.subtype
        enum: rtpfb_subtype

  rtpfb_transport_feedback_packet:
    seq:
      - id: base_sequence_number
        type: u2
      - id: packet_status_count
        type: u2
      - id: b4
        type: u4
      - id: remaining
        size-eos: true
    instances:
      reference_time:
        value: b4 >> 8
      fb_pkt_count:
        value: b4 & 0xff
      packet_status:
        size: 0
      recv_delta:
        size: 0

  psfb_packet:
    seq:
      - id: ssrc
        type: u4
      - id: ssrc_media_source
        type: u4
      - id: fci_block
        type:
          switch-on: fmt
          cases:
            'psfb_subtype::afb': psfb_afb_packet
        size-eos: true
    instances:
      fmt:
        value: _parent.subtype
        enum: psfb_subtype

  psfb_afb_packet:
    seq:
      - id: uid
        type: u4
      - id: contents
        type:
          switch-on: uid
          cases:
            0x52454d42: psfb_afb_remb_packet
        size-eos: true

  psfb_afb_remb_packet:
    seq:
      - id: num_ssrc_list
        type: u1
      - id: br_exp
        type: b6
      - id: br_mantissa
        type: b18
      - id: ssrc_list
        type: u4
        repeat: expr
        repeat-expr: num_ssrc_list
    instances:
      max_total_bitrate:
        value: br_mantissa * (1<<br_exp)

  bye_packet:
    seq:
      - id: ssrc
        type: u4
      - id: len_text
        type: u1
        if: _parent.length > 1
      - id: text
        type: str
        encoding: ascii
        size: len_text
        if: _parent.length > 1

enums:
  packet_type:
    192: fir
    193: nack
    195: ij
    200: sr
    201: rr
    202: sdes
    203: bye
    204: app
    205: rtpfb
    206: psfb
    207: xr
    208: avb
    209: rsi
  
  sdes_item_type:
    0: end
    1: cname
    2: name
    3: email
    4: phone
    5: loc
    6: tool
    7: note
    8: priv
  
  psfb_subtype:
    1: pli
    2: sli
    3: rpsi
    4: fir
    5: tstr
    6: tstn
    7: vbcm
    15: afb
  
  rtpfb_subtype:
    1: nack
    3: tmmbr
    4: tmmbn
    5: rrr
    15: transport_feedback