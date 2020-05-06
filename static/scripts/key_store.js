$(function () {
  $("#usernames").autocomplete({
    source: function (request, response) {
      $.ajax({
        url: "/api/user-keys/search_usernames/",
        dataType: "json",
        data: {
          term: request.term
        },
        success: function (data) {
          response($.map(data, function (item) {
            return {
              value: item.value,
              messaging_key: item.messaging_key_id,
              signing_key: item.signing_key_id
            }
          }));
        },
      });
    },
    response: function (event, ui) {
      if (!ui.content.length) {
        var noResult = { value: null, label: "No results found" };
        ui.content.push(noResult);
      } else {
        $("#currently-selected-user").empty();
      }
    },
    minLength: 1,
    select: function (event, ui) {
      setKeys(ui.item.messaging_key, ui.item.signing_key);
      if (ui.item.messaging_key) {
        $('#download-m-key').removeClass('disabled');
        $('#encrypt-msg').prop('disabled', false);
      } else {
        $('#download-m-key').addClass('disabled');
      }
      if (ui.item.signing_key) {
        $('#download-s-key').removeClass('disabled');
        $('#check-sig').prop('disabled', false);
      } else {
        $('#download-s-key').addClass('disabled');
      }
      $('#currently-selected-user').val(ui.item.value);
    }
  });
});

